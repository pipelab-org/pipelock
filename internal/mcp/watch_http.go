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
	n, err := r.reader.Read(p)
	if n > 0 {
		if sc := r.opts.scanner(); !r.inbound && sc != nil && watchCoreMatches(sc.ScanTextForDLP(r.opts.warnContext(), r.tail+string(p[:n])).Matches) {
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
			opts.watchListener.prepare(ParseMCPFrame(prefix), &opts)
			decision := watchInputDecision(prefix, logW, opts.watchSessionKey, opts)
			if decision.Blocked != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write(blockRequestResponse(*decision.Blocked))
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
	upReq.Header = r.Header.Clone()
	for name, values := range opts.UpstreamHeaders {
		upReq.Header[name] = append([]string(nil), values...)
	}
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
		w.Header()[name] = append([]string(nil), values...)
	}
	w.Header().Del(listenerSessionTokenHeader)
	opts.watchListener.complete(w, upResp.StatusCode, opts)
	if r.Method == http.MethodDelete && opts.watchListener != nil && upResp.StatusCode >= http.StatusOK && upResp.StatusCode < http.StatusMultipleChoices {
		opts.watchListener.states.forget(r.Header.Get(listenerSessionTokenHeader))
	}
	compressed := upResp.Header.Get("Content-Encoding") != "" && !strings.EqualFold(upResp.Header.Get("Content-Encoding"), "identity")
	if compressed {
		w.WriteHeader(upResp.StatusCode)
		_, _ = io.Copy(w, &watchCountingReader{reader: upResp.Body, opts: opts, reason: "compressed response", inbound: true})
		return
	}
	if strings.Contains(strings.ToLower(upResp.Header.Get("Content-Type")), "text/event-stream") {
		w.WriteHeader(upResp.StatusCode)
		flusher, _ := w.(http.Flusher)
		cfg := config.GenericSSEScanning{Enabled: true, Action: config.ActionBlock, MaxEventBytes: DefaultGenericSSEMaxEventBytes}
		err = ScanGenericSSEStreamWithOptions(r.Context(), &watchAccessReader{reader: upResp.Body, opts: opts}, w, flusher, opts.scanner(), &cfg, GenericSSEScanOptions{
			WatchOnly:   true,
			OnWatchOnly: opts.recordWatch,
			WatchEvent: func(event []byte) error {
				var inspected watchMessageBuffer
				_, scanErr := forwardWatchResponse(event, &inspected, logW, nil, opts)
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
		_, _ = io.Copy(w, &watchCountingReader{reader: io.MultiReader(bytes.NewReader(prefix), upResp.Body), opts: opts, reason: "response exceeds inspection ceiling", inbound: true})
		return
	}
	var output watchMessageBuffer
	if _, err := forwardWatchResponse(prefix, &output, logW, nil, opts); err != nil {
		http.Error(w, "response unavailable", http.StatusBadGateway)
		return
	}
	if !bytes.Equal(output.Bytes(), prefix) {
		w.Header().Del("Content-Length")
	}
	w.WriteHeader(upResp.StatusCode)
	_, _ = w.Write(output.Bytes())
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
