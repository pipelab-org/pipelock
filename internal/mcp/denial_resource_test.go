// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/mcp/provenance"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

type mcpResourceSink struct{ events []emit.Event }

func (s *mcpResourceSink) Emit(_ context.Context, event emit.Event) error {
	if event.Type == "blocked" {
		s.events = append(s.events, event)
	}
	return nil
}
func (*mcpResourceSink) Close() error { return nil }

// The released producers used tools/list and tool names. Content scanners
// already redacted their resources; routing metadata must not undo that.
func TestMCPDenialResourceContract(t *testing.T) {
	for _, tc := range []struct{ kind, want string }{
		{"tool_finding", "[redacted]"},
		{"tool_capacity", "[redacted]"},
		{"tool_inspection", "[redacted]"},
		{"provenance", "[redacted]"},
		{"response_content", "[redacted]"},
		{"media_finding", "[redacted]"},
		{"media_inspection", "[redacted]"},
		{"media_policy", "[redacted]"},
		{"dow", "[redacted]"},
		{"cee_entropy", "[redacted]"},
		{"cee_fragment", "[redacted]"},
		{"cee_fragment_limit", "[redacted]"},
		{"cee_owner", "[redacted]"},
		{"cee_capacity", "[redacted]"},
		{"policy", "mcp_input"},
		{"header_dlp", "mcp_listener_header"},
		{"kill_mcp_response", "mcp_response"},
		{"redirect_dlp", "mcp_redirect_output"},
		{"reply_content", "upstream_error_reply"},
		{"listener_admission", "mcp_listener"},
		{"startup_contract", "mcp_startup"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			var stream strings.Builder
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &stream)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			sink := &mcpResourceSink{}
			logger.SetEmitter(emit.NewEmitter("fixture", sink))
			dropMCPDenial(MCPProxyOpts{AuditLogger: logger}, mcpDenialAudit{kind: mcpDenialKind(tc.kind), pattern: "test finding"}, "response")
			var event struct {
				Resource string `json:"resource"`
			}
			if err := json.Unmarshal([]byte(stream.String()), &event); err != nil {
				t.Fatal(err)
			}
			if event.Resource != tc.want || len(sink.events) != 1 || sink.events[0].Fields["resource"] != tc.want {
				t.Fatalf("resource contract: local=%q external=%v want=%q", event.Resource, sink.events, tc.want)
			}
			if strings.HasPrefix(tc.kind, "tool_") && sink.events[0].Fields["scanner"] != "tool_scanning" {
				t.Fatalf("released tool scanner label changed: %v", sink.events[0].Fields)
			}
		})
	}
}

func TestMCPDenialDoWResourceRedaction(t *testing.T) {
	// These names include every fixed marker preserved by redactedContentFields.
	// A client choosing one as a tool name does not change the DoW contract.
	for _, toolName := range []string{"echo", "mcp_input", "mcp_listener_header", "mcp_response", "mcp_redirect_output", "upstream_error_reply", "mcp_listener", "mcp_startup"} {
		for _, surface := range []string{"stdio", "http"} {
			t.Run(toolName+"/"+surface, func(t *testing.T) {
				logger, events := newListenerEventLogger(t)
				opts := MCPProxyOpts{AuditLogger: logger, Scanner: testInputScanner(t), DoWCheck: func(_, _, _ string) (bool, string, string, string) {
					return false, config.ActionBlock, testDoWBudgetReason, testDoWBudgetType
				}}
				request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + toolName + `","arguments":{}}}`
				if surface == "http" {
					if scanHTTPInputDecision([]byte(request), io.Discard, "session", "session", opts).Blocked == nil {
						t.Fatal("DoW allowed")
					}
				} else {
					blocked := make(chan BlockedRequest, 1)
					ForwardScannedInput(transport.NewStdioReader(strings.NewReader(request)), transport.NewStdioWriter(io.Discard), io.Discard, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
					if len(blocked) != 1 {
						t.Fatal("DoW allowed")
					}
				}
				if !strings.Contains(events.String(), `"resource":"[redacted]"`) {
					t.Fatalf("released DoW resource changed: %s", events.String())
				}
			})
		}
	}
}

func TestMCPDenialListenerDirectionIndependentOfResource(t *testing.T) {
	for _, direction := range []string{"", "response"} {
		for _, kind := range []mcpDenialKind{"tool_finding", "tool_capacity", "tool_inspection", "provenance", "response_content", "media_finding", "media_inspection", "media_policy", "listener_admission", "listener_inspection", "header_dlp"} {
			t.Run(firstNonEmpty(direction, "input")+"/"+string(kind), func(t *testing.T) {
				logger, events := newListenerEventLogger(t)
				descriptor := mcpDenialAudit{kind: kind, pattern: "test finding"}
				writer := &mcpListenerDenialWriter{ResponseWriter: httptest.NewRecorder(), opts: MCPProxyOpts{AuditLogger: logger}, descriptor: &descriptor, direction: direction}
				if _, err := writer.Write([]byte(`{"error":"refused"}`)); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(events.String(), `"direction":"`+firstNonEmpty(direction, "input")+`"`) {
					t.Fatal(events.String())
				}
			})
		}
	}
}

// An upstream controls tool names. Naming an unsigned tool after a protocol
// marker must not lift the released provenance redaction.
func TestMCPDenialMarkerNamedUnsignedToolStaysRedacted(t *testing.T) {
	hexPub, _ := provenanceTestKeys(t)
	for _, toolName := range []string{"echo", "mcp_input", "mcp_listener_header", "mcp_response", "mcp_redirect_output", "upstream_error_reply", "mcp_listener", "mcp_startup"} {
		t.Run(toolName, func(t *testing.T) {
			logger, events := newListenerEventLogger(t)
			opts := buildTestOpts(testScannerWithAction(t, config.ActionWarn), withToolCfg(&tools.ToolScanConfig{Action: config.ActionWarn}))
			opts.AuditLogger = logger
			opts.ProvenanceCfg = &config.MCPToolProvenance{Enabled: true, Action: config.ActionWarn, Mode: config.ProvenanceModePipelock, TrustedKeys: []string{hexPub}, OfflineOnly: true}
			resp := buildUnsignedToolsListResponse(t, []provenance.ToolDef{{Name: toolName, Description: "Reads a file", InputSchema: json.RawMessage(`{"type":"object"}`)}})
			if _, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(string(resp)+"\n")), transport.NewStdioWriter(io.Discard), io.Discard, nil, opts); err != nil {
				t.Fatal(err)
			}
			got := events.String()
			if !strings.Contains(got, `"scanner":"provenance"`) || !strings.Contains(got, `"resource":"[redacted]"`) || strings.Contains(got, `"resource":"`+toolName+`"`) {
				t.Fatalf("unsigned tool resource lost its redaction: %s", got)
			}
		})
	}
}
