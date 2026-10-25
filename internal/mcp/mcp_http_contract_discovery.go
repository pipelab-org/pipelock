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
// cancellation; otherwise it retries, so one caller cannot refuse another's call.
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
}

func discoverMCPToolContract(d mcpContractDiscoveryRequest) error {
	// Discovery is finite work, unlike an upstream subscription. Reuse the
	// listener's existing idle-read allowance as the total acquisition budget.
	ctx, cancel := context.WithTimeout(d.request.Context(), upstreamIdleReadTimeout)
	defer cancel()
	cursor := ""
	cursors := make(map[string]bool)
	var definitions []tools.ToolDef
	// Each page is its own response, as for a client following the cursor. A
	// later page may repeat an unchanged definition when the inventory moves
	// during pagination; that is one contract. A conflicting repeat, or any
	// repeat within one page, stays a duplicate (MCP tools#tool-names).
	//
	// Pages are bounded by progress, not by a count: every page before the last
	// must name a tool no earlier page did. The baseline registry already caps
	// distinct names (maxBaselineTools), so a server cannot hold discovery open
	// past that capacity. MCP permits a non-final page without new tools; this
	// policy refuses that inventory rather than follow an unbounded cursor.
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
				NextCursor string          `json:"nextCursor"`
			} `json:"result"`
		}
		if err := json.Unmarshal(line, &response); err != nil {
			return fmt.Errorf("invalid discovery inventory: %w", err)
		}
		onPage := make(map[string]json.RawMessage)
		progressed := false
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
				progressed = true
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
			if !d.state.commitIfActive(func() { commitErr = d.state.baseline.SetToolHeaderBindings(unknown) }) {
				return errors.New("discovery principal was revoked")
			}
			return commitErr
		}
		cursor = response.Result.NextCursor
		if cursor == "" {
			return errors.New("tool absent from complete discovery inventory")
		}
		if cursors[cursor] {
			return errors.New("discovery inventory repeated a pagination cursor")
		}
		if !progressed {
			return errors.New("discovery inventory page named no new tool before its cursor")
		}
		cursors[cursor] = true
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

func (d mcpContractDiscoveryRequest) page(ctx context.Context, cursor string, remaining *int) ([]byte, error) {
	params := map[string]any{
		"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion":    d.request.Header.Get(listenerProtocolVersion),
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		},
	}
	if cursor != "" {
		params["cursor"] = cursor
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params})
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
	var reader transport.MessageReader = &transport.SingleMessageReader{Body: resp.Body}
	if isSSE {
		reader = transport.NewSSEReader(resp.Body)
	}
	tracker := NewStrictRequestTracker()
	tracker.TrackRequest(json.RawMessage("1"), "tools/list")
	opts := d.opts
	opts.WarnContext = ctx
	opts.toolContractDiscovery = true
	if cfg := opts.toolCfg(); cfg != nil {
		copyCfg := *cfg
		copyCfg.Baseline = d.state.baseline
		opts.ToolCfg = &copyCfg
		opts.ToolCfgFn = nil
	}
	for {
		line, err := reader.ReadMessage()
		if err != nil {
			return nil, fmt.Errorf("read discovery response: %w", err)
		}
		*remaining -= len(line)
		if *remaining < 0 {
			return nil, errors.New("discovery inventory exceeds response byte budget")
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
