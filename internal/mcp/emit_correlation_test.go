// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	mcpCorrHeader = "X-Correlation-Id"
	mcpCorrTag    = "mcp-case-0042"
)

type mcpCorrelationSink struct {
	mu     sync.Mutex
	events []emit.Event
}

func (s *mcpCorrelationSink) Emit(_ context.Context, ev emit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}

func (s *mcpCorrelationSink) Close() error { return nil }

func (s *mcpCorrelationSink) snapshot() []emit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]emit.Event(nil), s.events...)
}

func mcpCorrelationListener(t *testing.T, correlationHeader string) (string, *mcpCorrelationSink) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(toolPoisoningToolsListResponse))
	}))
	t.Cleanup(upstream.Close)

	sink := &mcpCorrelationSink{}
	emitter := emit.NewEmitter("mcp-correlation-test", sink)
	t.Cleanup(func() { _ = emitter.Close() })
	logger := audit.NewNop()
	logger.SetEmitter(emitter)

	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner:           testScannerForHTTP(t),
		ToolCfg:           &tools.ToolScanConfig{Action: config.ActionBlock, DetectDrift: true},
		AuditLogger:       logger,
		CorrelationHeader: correlationHeader,
	})
	return baseURL, sink
}

// postPoisonedToolsList sends tools/list to an upstream that answers with a poisoned
// tool description, so the listener blocks the response and emits a block
// event for this HTTP request.
func postPoisonedToolsList(t *testing.T, baseURL, tag string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsList))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if tag != "" {
		req.Header.Set(mcpCorrHeader, tag)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(respBody), "-32000") {
		t.Fatalf("expected tool poisoning block, got: %s", respBody)
	}
}

func TestEmitCorrelation_MCPHTTPListener(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		tag    string
		want   string
	}{
		{name: "tag carried", header: mcpCorrHeader, tag: mcpCorrTag, want: mcpCorrTag},
		{name: "header absent", header: mcpCorrHeader, tag: "", want: ""},
		{name: "feature off", header: "", tag: mcpCorrTag, want: ""},
		{name: "oversized omitted", header: mcpCorrHeader, tag: strings.Repeat("t", audit.CorrelationIDMaxBytes+1), want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			baseURL, sink := mcpCorrelationListener(t, tt.header)
			postPoisonedToolsList(t, baseURL, tt.tag)
			events := sink.snapshot()
			if len(events) == 0 {
				t.Fatal("listener block emitted no events")
			}
			for _, ev := range events {
				got, ok := ev.Fields[audit.FieldCorrelationID]
				if tt.want == "" {
					if ok {
						t.Fatalf("%s carries correlation_id %v, want absent", ev.Type, got)
					}
					continue
				}
				if got != tt.want {
					t.Fatalf("%s correlation_id = %v, want %q; fields=%v", ev.Type, got, tt.want, ev.Fields)
				}
			}
		})
	}
}

// Requests on one listener must not share a tag: the per-request logger copy
// is scoped to its own HTTP request.
func TestEmitCorrelation_MCPHTTPListenerPerRequest(t *testing.T) {
	t.Parallel()
	baseURL, sink := mcpCorrelationListener(t, mcpCorrHeader)
	postPoisonedToolsList(t, baseURL, mcpCorrTag)
	first := len(sink.snapshot())
	postPoisonedToolsList(t, baseURL, "")
	events := sink.snapshot()
	if first == 0 || len(events) <= first {
		t.Fatalf("event counts first=%d total=%d, want both requests to emit", first, len(events))
	}
	for _, ev := range events[first:] {
		if got, ok := ev.Fields[audit.FieldCorrelationID]; ok {
			t.Fatalf("second request inherited correlation_id %v from the first", got)
		}
	}
}

// Listener-writer and input-pipeline refusals must use the same vetted tag.
// Early admission refusals never copy a header that has not been vetted.
func TestEmitCorrelation_MCPHTTPListenerRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, tag, want, label string
		headers                func(http.Header)
	}{
		{"header_dlp", mcpCorrTag, mcpCorrTag, scanner.AuditMCPHeaderDLP, func(h http.Header) { h.Set("Authorization", "Bearer AKIA"+"Z7VRSQ5TJN2XMPLQ") }},
		{"tool_policy", mcpCorrTag, mcpCorrTag, scanner.AuditMCPToolPolicy, nil},
		{"invalid_tag", "invalid tag", "", scanner.AuditMCPToolPolicy, nil},
		{"secret_tag", "AKIA" + "Z7VRSQ5TJN2XMPLQ", "", scanner.AuditMCPToolPolicy, nil},
		{"absent_tag", "", "", scanner.AuditMCPToolPolicy, nil},
		{"origin_before_vetting", mcpCorrTag, "", scanner.AuditMCPProtocol, func(h http.Header) { h.Set("Origin", "https://untrusted.example") }},
		{"protocol_before_vetting", mcpCorrTag, "", scanner.AuditMCPProtocol, func(h http.Header) { h.Set("MCP-Protocol-Version", "invalid") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &mcpCorrelationSink{}
			emitter := emit.NewEmitter("correlation-test", sink)
			t.Cleanup(func() { _ = emitter.Close() })
			logger := audit.NewNop()
			logger.SetEmitter(emitter)
			upstream, _ := newWireContractUpstream(t)
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), AuditLogger: logger, CorrelationHeader: mcpCorrHeader,
				PolicyCfg: buildPolicyConfig(config.ActionBlock, []config.ToolPolicyRule{{Name: "deny-echo", ToolPattern: "^echo$", Action: config.ActionBlock}}),
			}
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			headers := currentWireHeaders("tools/call", "echo")
			if tc.tag != "" {
				headers.Set(mcpCorrHeader, tc.tag)
			}
			if tc.headers != nil {
				tc.headers(headers)
			}
			postWireContractRequest(t, baseURL, currentWireBody(1, "tools/call", `"name":"echo","arguments":{}`), headers)
			blocked := 0
			for _, ev := range sink.snapshot() {
				if ev.Type != "blocked" {
					continue
				}
				blocked++
				got, present := ev.Fields[audit.FieldCorrelationID]
				if ev.Fields["scanner"] != tc.label || (tc.want == "" && present) || (tc.want != "" && got != tc.want) {
					t.Fatalf("block fields=%v, want scanner=%s correlation_id=%q", ev.Fields, tc.label, tc.want)
				}
			}
			if blocked != 1 {
				t.Fatalf("blocked events=%d, want 1", blocked)
			}
		})
	}
}
