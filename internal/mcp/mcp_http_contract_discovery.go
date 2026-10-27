// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/responseencoding"
)

// mcpReceiptLayerHeaderContract names the x-mcp-header contract check in a
// blocked outcome receipt.
const mcpReceiptLayerHeaderContract = "mcp_header_contract"

type mcpContractDiscoveryFlight struct {
	done chan struct{}
	tool string
	err  error
	// leaderEnded marks a failure caused by the initiating request ending. It
	// says nothing about the upstream contract, so followers retry it.
	leaderEnded bool
}

// acquireToolContract returns a read hold covering contract comparison. Private
// discovery and client-visible lists use the SAME exclusive lock across fetch,
// inspection and commit. A newer list therefore cannot be overwritten by an
// older discovery, including one that had to wait for that list. A follower
// shares a failure only for the tool it asked about, and never the leader's own
// cancellation; otherwise it retries. A shared failure can still come from the
// leader's upstream credentials when callers of one principal send different
// ones; that refusal lasts only for the overlap and a retry discovers again.
func (state *mcpListenerClientState) acquireToolContract(ctx context.Context, name string, discover func() error) (func(), error) {
	for {
		state.discoveryMu.Lock()
		flight := state.discovery
		if flight == nil && state.baseline.HeaderContract(name).State != tools.HeaderContractUnknown {
			state.discoveryMu.Unlock()
			if err := state.contractMu.RLock(ctx); err != nil {
				return nil, err
			}
			if state.baseline.HeaderContract(name).State != tools.HeaderContractUnknown {
				return state.contractMu.RUnlock, nil
			}
			state.contractMu.RUnlock()
			continue
		}
		leader := flight == nil

		if leader {
			flight = &mcpContractDiscoveryFlight{done: make(chan struct{}), tool: name}
			state.discovery = flight
		}
		state.discoveryMu.Unlock()
		if leader {
			flight.err = state.contractMu.Lock(ctx)
			if flight.err == nil {
				// A client list or another discovery may have won the lock.
				if state.baseline.HeaderContract(name).State == tools.HeaderContractUnknown {
					flight.err = discover()
				}
				state.contractMu.Unlock()
			}
			flight.leaderEnded = ctx.Err() != nil
			state.discoveryMu.Lock()
			state.discovery = nil
			close(flight.done)
			state.discoveryMu.Unlock()
			if flight.err != nil {
				return nil, flight.err
			}
		} else {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-flight.done:
			}
			if flight.err != nil && flight.tool == name && !flight.leaderEnded {
				return nil, flight.err
			}
		}
		// Reacquire through writer preference: a queued client list must get
		// to publish its newer contract before this call compares mirrors.
	}
}

type mcpContractDiscoveryRequest struct {
	request  *http.Request
	client   *http.Client
	upstream string
	opts     MCPProxyOpts
	state    *mcpListenerClientState
	log      io.Writer
	tool     string
	bridge   *transport.HTTPClient
}

func discoverMCPToolContract(d mcpContractDiscoveryRequest) error {
	// Discovery is finite work, unlike an upstream subscription. Reuse the
	// listener's existing idle-read allowance as the total acquisition budget.
	ctx, cancel := context.WithTimeout(d.request.Context(), upstreamIdleReadTimeout)
	defer cancel()
	var cursor *string
	cursors := make(map[string]bool)
	var definitions []tools.ToolDef
	// Each page is its own response, as for a client following the cursor. A
	// later page may repeat an unchanged definition when the inventory moves
	// during pagination; that is one contract. A conflicting repeat, or any
	// repeat within one page, stays a duplicate (MCP tools#tool-names).
	//
	// Page size belongs to the server, and a page may carry no new tools
	// (MCP utilities/pagination), so no page count or per-page progress is
	// required. The response byte budget and the deadline above bound the whole
	// walk, and a repeated cursor ends it.
	earlier := make(map[string]json.RawMessage)
	remaining := transport.MaxLineSize
	for {
		line, err := d.page(ctx, cursor, &remaining)
		if err != nil {
			return err
		}
		var response struct {
			Result struct {
				Tools      []tools.ToolDef `json:"tools"`
				NextCursor *string         `json:"nextCursor"`
			} `json:"result"`
		}
		if err := json.Unmarshal(line, &response); err != nil {
			return fmt.Errorf("invalid discovery inventory: %w", err)
		}
		onPage := make(map[string]json.RawMessage)
		for _, def := range response.Result.Tools {
			if schema, repeated := earlier[def.Name]; repeated {
				if _, again := onPage[def.Name]; !again && sameToolSchema(schema, def.InputSchema) {
					onPage[def.Name] = schema
					continue
				}
			}
			if _, again := onPage[def.Name]; !again {
				onPage[def.Name] = def.InputSchema
			}
			definitions = append(definitions, def)
		}
		for name, schema := range onPage {
			if _, repeated := earlier[name]; !repeated {
				earlier[name] = schema
			}
		}
		if !d.state.baseline.CanAdmitHeaderBindings(definitions) {
			return tools.ErrBaselineCapacity
		}
		found := false
		for _, def := range response.Result.Tools {
			found = found || def.Name == d.tool
		}
		if found {
			// Do not replace an already-observed sibling's stronger state.
			unknown := definitions[:0]
			for _, def := range definitions {
				if d.state.baseline.HeaderContract(def.Name).State == tools.HeaderContractUnknown {
					unknown = append(unknown, def)
				}
			}
			var commitErr error
			if err := ctx.Err(); err != nil {
				return err
			}
			if !d.state.commitIfActive(func() {
				// Another response may have held the commit lock past the
				// acquisition deadline or the caller's cancellation.
				commitErr = ctx.Err()
				if commitErr == nil {
					commitErr = d.state.baseline.SetToolHeaderBindings(unknown)
				}
			}) {
				return errors.New("discovery principal was revoked")
			}
			return commitErr
		}
		cursor = response.Result.NextCursor
		if cursor == nil {
			return errors.New("tool absent from complete discovery inventory")
		}
		if cursors[*cursor] {
			return errors.New("discovery inventory repeated a pagination cursor")
		}
		cursors[*cursor] = true
	}
}

// sameToolSchema compares decoded schemas, so key order and spacing do not
// make one repeated definition read as two conflicting ones.
func sameToolSchema(a, b json.RawMessage) bool {
	var left, right any
	if extract.DecodeJSON(a, &left) != nil || extract.DecodeJSON(b, &right) != nil {
		return bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b))
	}
	return reflect.DeepEqual(left, right)
}

func (d mcpContractDiscoveryRequest) page(ctx context.Context, cursor *string, remaining *int) ([]byte, error) {
	params := map[string]any{
		"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion":    d.request.Header.Get(listenerProtocolVersion),
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		},
	}
	if cursor != nil {
		params["cursor"] = *cursor
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params})
	var reader transport.MessageReader
	var budget *io.LimitedReader
	if d.bridge != nil {
		headers := http.Header{}
		headers.Set(listenerMCPMethod, "tools/list")
		headers.Set(listenerProtocolVersion, d.request.Header.Get(listenerProtocolVersion))
		var err error
		reader, err = d.bridge.SendMessageWithOptions(ctx, body, transport.HTTPMessageOptions{Headers: headers, ResponseByteBudget: remaining, PreserveSession: true})
		if err != nil {
			return nil, fmt.Errorf("upstream discovery request: %w", err)
		}
		if closer, ok := reader.(io.Closer); ok {
			defer func() { _ = closer.Close() }()
		}
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.upstream, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("build discovery request: %w", err)
		}
		for name, values := range d.opts.UpstreamHeaders {
			req.Header[name] = append([]string(nil), values...)
		}
		forwardListenerUpstreamHeaders(req, d.request, false)
		// Authentication is identical to the call; routing belongs to this list.
		for name := range req.Header {
			if strings.HasPrefix(strings.ToLower(name), mcpParamHeaderPrefix) {
				req.Header.Del(name)
			}
		}
		req.Header.Del(listenerMCPName)
		req.Header.Set(listenerMCPMethod, "tools/list")
		req.Header.Set(listenerProtocolVersion, d.request.Header.Get(listenerProtocolVersion))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		responseencoding.RequestIdentity(req.Header)
		resp, err := d.client.Do(req)
		if err != nil {
			return nil, errors.New("upstream discovery request failed")
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("upstream discovery returned HTTP %d", resp.StatusCode)
		}
		resp.Body = newIdleTimeoutReader(resp.Body, upstreamIdleReadTimeout)
		isSSE := transport.HasSingleSSEContentType(resp.Header)
		if responseencoding.HasNonIdentityContentEncoding(resp.Header) {
			if isSSE {
				return nil, errors.New("compressed discovery stream cannot be inspected")
			}
			if err := responseencoding.DecodeResponse(resp); err != nil {
				return nil, errors.New("discovery response encoding cannot be inspected")
			}
		}
		// Charge decoded response bytes before framing removes SSE comments,
		// metadata and separators. One extra byte distinguishes exhaustion from
		// a response that ends exactly at the remaining acquisition budget.
		budget = &io.LimitedReader{R: resp.Body, N: int64(*remaining) + 1}
		reader = &transport.SingleMessageReader{Body: io.NopCloser(budget)}
		if isSSE {
			reader = transport.NewSSEReader(budget)
		}
	}
	tracker := NewStrictRequestTracker()
	tracker.TrackRequest(json.RawMessage("1"), "tools/list")
	opts := d.opts
	opts.WarnContext = ctx
	opts.toolContractDiscovery = true
	// Nothing in this inventory reaches the agent, so there is nothing for an
	// operator to approve, and an approval wait would hold the principal's
	// contract lock past the request. Without an approver an ask finding
	// blocks, which refuses discovery; a client tools/list takes the normal
	// approval path and establishes the contracts.
	opts.Approver = nil
	if cfg := opts.toolCfg(); cfg != nil {
		copyCfg := *cfg
		copyCfg.Baseline = d.state.baseline
		opts.ToolCfg = &copyCfg
		opts.ToolCfgFn = nil
	}
	for {
		var before int64
		if budget != nil {
			before = budget.N
		}
		line, err := reader.ReadMessage()
		if budget != nil {
			*remaining -= int(before - budget.N)
		}
		if *remaining < 0 {
			return nil, errors.New("discovery inventory exceeds response byte budget")
		}
		if err != nil {
			return nil, fmt.Errorf("read discovery response: %w", err)
		}
		var buf bytes.Buffer
		_, err = ForwardScanned(&transport.SingleMessageReader{Body: io.NopCloser(bytes.NewReader(line))}, transport.NewStdioWriter(&buf), d.log, tracker, opts)
		if err != nil {
			return nil, fmt.Errorf("inspect discovery response: %w", err)
		}
		if ParseMCPFrame(line).Method != "" {
			// Server notifications are inspected but never delivered as client
			// inventory, nor used to resolve held inventory approval.
			continue
		}
		var response struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		inspected := bytes.TrimSpace(buf.Bytes())
		if json.Unmarshal(inspected, &response) != nil || len(response.Error) != 0 || tools.ClassifyToolsListResult(response.Result) != tools.ToolsListValid {
			return nil, errors.New("discovery response was refused or is not a complete inspectable tools/list result")
		}
		return inspected, nil
	}
}
