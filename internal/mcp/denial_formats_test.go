// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/emit"
)

// Exercise the real finalizer and each external encoder. Catalog markers must
// survive provenance-based redaction; the released tool resource must not.
func TestMCPDenialResourcesAcrossFormats(t *testing.T) {
	for _, tc := range []struct{ kind, resource string }{
		{"policy", "mcp_input"},
		{"header_dlp", "mcp_listener_header"},
		{"kill_mcp_response", "mcp_response"},
		{"redirect_dlp", "mcp_redirect_output"},
		{"reply_content", "upstream_error_reply"},
		{"listener_admission", "mcp_listener"},
		{"startup_contract", "mcp_startup"},
		{"tool_finding", "[redacted]"},
		{"tool_capacity", "[redacted]"},
		{"tool_inspection", "[redacted]"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			logger := audit.NewNop()
			sink := &mcpResourceSink{}
			logger.SetEmitter(emit.NewEmitter("format-test", sink))
			t.Cleanup(logger.Close)
			dropMCPDenial(MCPProxyOpts{AuditLogger: logger}, mcpDenialAudit{kind: mcpDenialKind(tc.kind), pattern: "fixture"}, "response")
			if len(sink.events) != 1 {
				t.Fatalf("blocked events=%d, want 1", len(sink.events))
			}
			event := sink.events[0]
			encoded, err := json.Marshal(event.Fields)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(encoded), `"resource":"`+tc.resource+`"`) {
				t.Fatalf("JSON resource lost: %s", encoded)
			}
			cef := emit.FormatCEFEvent(event, "test")
			if !strings.Contains(cef, "destinationServiceName="+tc.resource) {
				t.Fatalf("CEF resource lost: %s", cef)
			}
			var ocsf struct {
				Endpoint struct {
					Hostname string `json:"hostname"`
				} `json:"dst_endpoint"`
			}
			if err := json.Unmarshal([]byte(emit.FormatOCSFEvent(event, "test")), &ocsf); err != nil {
				t.Fatal(err)
			}
			if ocsf.Endpoint.Hostname != tc.resource {
				t.Fatalf("OCSF resource=%q, want %q", ocsf.Endpoint.Hostname, tc.resource)
			}
			assertMCPDenialOTLPResource(t, event, tc.resource)
		})
	}
}

func assertMCPDenialOTLPResource(t *testing.T, event emit.Event, want string) {
	t.Helper()
	bodies := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		bodies <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	sink, err := emit.NewOTLPSink(server.URL, "test", emit.SeverityInfo, nil, 5*time.Second, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	var body []byte
	select {
	case body = <-bodies:
	default:
		t.Fatal("OTLP sink closed without delivering the event")
	}
	field, typ, n := protowire.ConsumeTag(body)
	if field != 1 || typ != protowire.BytesType || n < 0 {
		t.Fatalf("invalid OTLP request wrapper: field=%d type=%v length=%d", field, typ, n)
	}
	resourceBytes, n := protowire.ConsumeBytes(body[n:])
	if n < 0 {
		t.Fatal("invalid OTLP resource logs")
	}
	var resource logspb.ResourceLogs
	if err := proto.Unmarshal(resourceBytes, &resource); err != nil {
		t.Fatal(err)
	}
	for _, scope := range resource.ScopeLogs {
		for _, record := range scope.LogRecords {
			for _, attr := range record.Attributes {
				if attr.Key == "resource" && attr.Value.GetStringValue() == want {
					return
				}
			}
		}
	}
	t.Fatalf("OTLP resource %q missing: %v", want, &resource)
}
