// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

type watchCountingReader struct {
	reader  io.Reader
	opts    MCPProxyOpts
	reason  string
	inbound bool
	a2a     bool
	tail    string
}

func (r *watchCountingReader) Read(p []byte) (int, error) {
	if !r.opts.watchListener.active() {
		r.opts.recordWatch("listener_access", "listener identity revoked", config.ActionBlock, 0, true)
		return 0, errors.New("listener identity revoked")
	}
	if r.opts.KillSwitch != nil && r.opts.KillSwitch.IsActive() {
		r.opts.recordWatch("kill_switch", "operator kill switch", config.ActionBlock, 0, true)
		return 0, errors.New("kill switch enforced in watch-only")
	}
	if err := r.opts.checkServerIdentity(); err != nil {
		r.opts.recordWatch("identity", "server identity no longer authorized", config.ActionBlock, 0, true)
		return 0, err
	}
	n, err := r.reader.Read(p)
	if identityErr := r.opts.checkServerIdentity(); identityErr != nil {
		return 0, identityErr
	}
	if n > 0 {
		if sc := r.opts.scanner(); (!r.inbound || r.a2a) && sc != nil && watchCoreMatches(sc.ScanTextForDLP(r.opts.warnContext(), r.tail+string(p[:n])).Matches) {
			r.opts.recordWatch("dlp", "core credential floor", config.ActionBlock, 0, true)
			return 0, errors.New("core credential floor enforced in watch-only")
		}
		r.tail = advanceSSERollingTail(r.tail, p[:n], false, "")
		r.opts.recordWatch("mcp_http", r.reason, "uninspected", int64(n), false)
	}
	return n, err
}

type watchMessageBuffer struct{ bytes.Buffer }

func (w *watchMessageBuffer) WriteMessage(msg []byte) error { _, err := w.Write(msg); return err }

// serveWatchMCPHTTP runs after the listener's host, origin and authentication
// admission. It preserves the upstream HTTP status, framing and content while
// applying the same per-message observation decisions as stdio.
func serveWatchMCPHTTP(w http.ResponseWriter, r *http.Request, upstreamURL string, client *http.Client, logW io.Writer, opts MCPProxyOpts) {
	opts.WatchOnly, opts.WatchOnlyFn = true, nil
	if opts.watchSessionKey == "" {
		opts.watchSessionKey = newMCPListenerTransientState().key
	}
	if opts.KillSwitch != nil && opts.KillSwitch.IsActive() {
		opts.recordWatch("kill_switch", "operator kill switch", config.ActionBlock, 0, true)
		http.Error(w, "kill switch enforced in watch-only", http.StatusForbidden)
		return
	}
	var body io.Reader
	var requestFrame MCPFrame
	delivered := false
	defer func() {
		if opts.watchListener != nil && opts.watchListener.admitted && !delivered {
			opts.watchListener.states.forget(opts.watchListener.state.token)
		}
	}()
	if r.Method != http.MethodPost {
		if r.Header.Get(listenerProtocolVersion) >= currentMCPVersion {
			http.Error(w, "current MCP protocol requires POST", http.StatusMethodNotAllowed)
			return
		}
		if hasMCPPOSTOnlyHeaders(r.Header) {
			http.Error(w, "MCP routing headers require POST body validation", http.StatusBadRequest)
			return
		}
	}
	if r.Method == http.MethodPost && (r.Body == nil || r.Body == http.NoBody) {
		opts.recordWatch("mcp_protocol", "empty MCP request body", config.ActionBlock, 0, true)
		http.Error(w, "empty MCP request body", http.StatusBadRequest)
		return
	}
	if r.Body != nil && r.Body != http.NoBody {
		prefix, err := io.ReadAll(io.LimitReader(r.Body, int64(transport.MaxLineSize)+1))
		if err != nil {
			opts.recordWatch("transport", "request read failed", config.ActionBlock, 0, true)
			http.Error(w, "request read failed", http.StatusBadRequest)
			return
		}
		if len(prefix) <= transport.MaxLineSize {
			requestFrame = ParseMCPFrame(prefix)
			if !routingHeaderMatchesFrame(r.Header, requestFrame) || !currentProtocolHeadersMatchFrame(r.Header, requestFrame) {
				http.Error(w, "MCP routing header does not match the request body", http.StatusBadRequest)
				return
			}
			opts.watchListener.prepare(requestFrame, &opts)
			decision := watchInputDecision(prefix, logW, opts.watchSessionKey, opts)
			if decision.Blocked != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write(blockRequestResponse(*decision.Blocked))
				return
			}
			if state := opts.watchListener; state != nil && !state.bound && state.requireToken && listenerMethodRequiresPrincipal(requestFrame.Method) {
				opts.recordWatch("session_binding", "listener session token required", config.ActionBlock, 0, true)
				http.Error(w, "listener session token required", http.StatusForbidden)
				return
			}
			body = bytes.NewReader(decision.ForwardMessage)
		} else {
			opts.recordWatch("mcp_protocol", "outbound message exceeds inspection ceiling", config.ActionBlock, 0, true)
			http.Error(w, "outbound inspection limit enforced in watch-only", http.StatusRequestEntityTooLarge)
			return
		}
	}
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, body)
	if err != nil {
		http.Error(w, "upstream request unavailable", http.StatusBadGateway)
		return
	}
	upReq.Header = opts.UpstreamHeaders.Clone()
	if upReq.Header == nil {
		upReq.Header = make(http.Header)
	}
	for _, name := range []string{"Content-Type", "Accept"} {
		forwardIfOperatorUnset(upReq, r, name)
	}
	forwardListenerUpstreamHeaders(upReq, r, r.Method == http.MethodGet)
	upReq.Header.Del("Proxy-Authorization")
	upReq.Header.Del(listenerSessionTokenHeader)
	agentHeaders := r.Header.Clone()
	agentHeaders.Del(listenerSessionTokenHeader)
	if watchMCPHeaders(r.Context(), agentHeaders, upstreamURL, opts) {
		http.Error(w, "core credential floor enforced in watch-only", http.StatusForbidden)
		return
	}
	if opts.ServerIdentityHeadersFn != nil {
		headers := upReq.Header.Clone()
		opts.ServerIdentityFn = func() ServerIdentity { return opts.ServerIdentityHeadersFn(headers) }
	}
	if err := opts.checkServerIdentity(); err != nil || !opts.watchListener.active() {
		opts.recordWatch("identity", "server or listener identity no longer authorized", config.ActionBlock, 0, true)
		http.Error(w, "identity no longer authorized", http.StatusForbidden)
		return
	}
	if gate, err := evaluateMCPUpstreamGate(r.Context(), upstreamURL, opts); err != nil || gate.Verdict == config.ActionBlock {
		http.Error(w, "upstream refused", http.StatusForbidden)
		return
	}
	if r.ContentLength < 0 {
		upReq.ContentLength = r.ContentLength
	}
	upResp, err := client.Do(upReq)
	if err != nil {
		opts.recordWatch("transport", "upstream unavailable", config.ActionBlock, 0, true)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = upResp.Body.Close() }()
	for name, values := range upResp.Header {
		if !watchReservedMCPHeader(name) && !strings.EqualFold(name, "Trailer") {
			w.Header()[name] = append([]string(nil), values...)
		}
	}
	w.Header().Del(listenerSessionTokenHeader)
	if r.Method == http.MethodDelete && opts.watchListener != nil && upResp.StatusCode >= http.StatusOK && upResp.StatusCode < http.StatusMultipleChoices {
		state := opts.watchListener
		if !state.principal {
			if state.requireToken {
				state.states.forget(r.Header.Get(listenerSessionTokenHeader))
			} else {
				state.states.forgetLegacySession(r.Header.Get("Mcp-Session-Id"))
			}
		}
	}
	var inventoryCommits, inventoryReleases []func()
	opts.toolInventoryDelivery = func(commit, release func()) {
		inventoryCommits = append(inventoryCommits, commit)
		inventoryReleases = append(inventoryReleases, release)
	}
	defer func() {
		for _, release := range inventoryReleases {
			release()
		}
	}()
	commitInventory := func() {
		for _, commit := range inventoryCommits {
			commit()
		}
		inventoryCommits = nil
		inventoryReleases = nil
	}
	var tracker *RequestTracker
	if requestFrame.Method != "" && requestFrame.ID != nil {
		tracker = NewStrictRequestTrackerFor(requestFrame.ID, requestFrame.Method)
	}
	a2a := opts.a2aCfg() != nil && opts.a2aCfg().Enabled && IsA2AMethod(requestFrame.Method)
	compressed := upResp.Header.Get("Content-Encoding") != "" && !strings.EqualFold(upResp.Header.Get("Content-Encoding"), "identity")
	if compressed {
		w.WriteHeader(upResp.StatusCode)
		_, err = io.Copy(w, &watchCountingReader{reader: upResp.Body, opts: opts, reason: "compressed response", inbound: true, a2a: a2a})
		delivered = err == nil
		return
	}
	if strings.Contains(strings.ToLower(upResp.Header.Get("Content-Type")), "text/event-stream") {
		if state := opts.watchListener; state != nil && state.setup {
			var prelude bytes.Buffer
			peek := transport.NewWatchSSEReader(io.TeeReader(io.LimitReader(upResp.Body, int64(transport.MaxLineSize)+1), &prelude), transport.MaxLineSize, func([]byte) error { return errors.New("initialization response exceeds inspection ceiling") })
			for prelude.Len() <= transport.MaxLineSize {
				msg, readErr := peek.ReadMessage()
				if readErr != nil || len(msg) != 0 {
					if readErr == nil {
						state.complete(w, upResp.StatusCode, msg, opts)
					}
					break
				}
			}
			upResp.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(prelude.Bytes()), upResp.Body), upResp.Body}
		}
		w.WriteHeader(upResp.StatusCode)
		flusher, _ := w.(http.Flusher)
		cfg := config.GenericSSEScanning{Enabled: true, Action: config.ActionBlock, MaxEventBytes: DefaultGenericSSEMaxEventBytes}
		err = ScanGenericSSEStreamWithOptions(r.Context(), &watchAccessReader{reader: upResp.Body, opts: opts}, w, flusher, opts.scanner(), &cfg, GenericSSEScanOptions{
			WatchOnly:           true,
			OnWatchOnly:         opts.recordWatch,
			WatchEventDelivered: commitInventory,
			WatchEvent: func(event []byte) error {
				var inspected watchMessageBuffer
				_, scanErr := forwardWatchResponse(event, &inspected, logW, tracker, opts)
				if scanErr != nil {
					return scanErr
				}
				if !bytes.Equal(inspected.Bytes(), event) {
					return fmt.Errorf("%w: enforced in watch-only", ErrSSEStreamFinding)
				}
				return nil
			},
		})
		if err != nil && logW != nil {
			_, _ = fmt.Fprintf(logW, "pipelock: watch-only SSE stopped: %v\n", err)
		}
		delivered = err == nil
		return
	}
	prefix, err := io.ReadAll(io.LimitReader(upResp.Body, int64(transport.MaxLineSize)+1))
	if err != nil {
		opts.recordWatch("transport", "upstream response read failed", config.ActionBlock, 0, true)
		http.Error(w, "upstream response unavailable", http.StatusBadGateway)
		return
	}
	if len(prefix) > transport.MaxLineSize {
		w.WriteHeader(upResp.StatusCode)
		_, err = io.Copy(w, &watchCountingReader{reader: io.MultiReader(bytes.NewReader(prefix), upResp.Body), opts: opts, reason: "response exceeds inspection ceiling", inbound: true, a2a: a2a})
		delivered = err == nil
		return
	}
	var output watchMessageBuffer
	if _, err := forwardWatchResponse(prefix, &output, logW, tracker, opts); err != nil {
		http.Error(w, "response unavailable", http.StatusBadGateway)
		return
	}
	if !bytes.Equal(output.Bytes(), prefix) {
		w.Header().Del("Content-Length")
	}
	opts.watchListener.complete(w, upResp.StatusCode, output.Bytes(), opts)
	w.WriteHeader(upResp.StatusCode)
	n, err := w.Write(output.Bytes())
	delivered = err == nil && n == output.Len()
	if delivered {
		if err := http.NewResponseController(w).Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			delivered = false
		}
	}
	if delivered {
		commitInventory()
	}
}

// watchAccessReader checks live access controls without changing byte accounting.
type watchAccessReader struct {
	reader io.Reader
	opts   MCPProxyOpts
}

func (r *watchAccessReader) Read(p []byte) (int, error) {
	if !r.opts.watchListener.active() {
		r.opts.recordWatch("listener_access", "listener identity revoked", config.ActionBlock, 0, true)
		return 0, errors.New("listener identity revoked")
	}
	if r.opts.KillSwitch != nil && r.opts.KillSwitch.IsActive() {
		r.opts.recordWatch("kill_switch", "operator kill switch", config.ActionBlock, 0, true)
		return 0, errors.New("kill switch enforced in watch-only")
	}
	if err := r.opts.checkServerIdentity(); err != nil {
		r.opts.recordWatch("identity", "server identity no longer authorized", config.ActionBlock, 0, true)
		return 0, err
	}
	return r.reader.Read(p)
}

// The proxy owns decision evidence; upstreams cannot attest its decisions.
func watchReservedMCPHeader(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "x-pipelock-") || strings.EqualFold(name, listenerSessionTokenHeader)
}
