// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Marker preservation is a property of who chose the resource, not of its
// spelling. A tool name that equals a marker keeps its released redaction.
func TestMCPProtocolMarkerRequiresFinalizerProvenance(t *testing.T) {
	markers := []string{"mcp_input", "mcp_listener_header", "mcp_response", "mcp_redirect_output", "upstream_error_reply", "mcp_listener", "mcp_startup"}
	for _, marker := range markers {
		for _, tc := range []struct {
			name    string
			ctx     func(t *testing.T) LogContext
			scanner string
			want    string
		}{
			{"producer_tool_name", func(t *testing.T) LogContext { return mustMCPMarkerTestContext(t, marker) }, "provenance", "[redacted]"},
			{"producer_dow_target", func(t *testing.T) LogContext { return mustMCPMarkerTestContext(t, marker) }, "denial_of_wallet", "[redacted]"},
			{"finalizer_marker", func(t *testing.T) LogContext { return mustMCPMarkerTestContext(t, marker).WithMCPProtocolMarker() }, "provenance", marker},
			{"finalizer_dow", func(t *testing.T) LogContext { return mustMCPMarkerTestContext(t, marker).WithMCPProtocolMarker() }, "denial_of_wallet", "[redacted]"},
			{"non_mcp_context", func(*testing.T) LogContext { return NewResourceLogContext("MCP", marker).WithMCPProtocolMarker() }, "provenance", "[redacted]"},
		} {
			t.Run(marker+"/"+tc.name, func(t *testing.T) {
				var buf bytes.Buffer
				l, err := NewWithStream("json", "stdout", "", true, true, &buf)
				if err != nil {
					t.Fatal(err)
				}
				l.LogAnomaly(tc.ctx(t), tc.scanner, "fixture", 0)
				l.LogBlocked(tc.ctx(t), tc.scanner, "fixture")
				l.Close()
				lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
				if len(lines) != 2 {
					t.Fatalf("events=%d: %s", len(lines), buf.String())
				}
				for _, line := range lines {
					var event struct {
						Event    string `json:"event"`
						Resource string `json:"resource"`
					}
					if err := json.Unmarshal(line, &event); err != nil {
						t.Fatal(err)
					}
					if event.Resource != tc.want {
						t.Fatalf("%s resource=%q want=%q", event.Event, event.Resource, tc.want)
					}
				}
			})
		}
	}
	t.Run("finalizer_non_marker", func(t *testing.T) {
		var buf bytes.Buffer
		l, err := NewWithStream("json", "stdout", "", true, true, &buf)
		if err != nil {
			t.Fatal(err)
		}
		l.LogBlocked(mustMCPMarkerTestContext(t, "server_response").WithMCPProtocolMarker(), "response_scan", "fixture")
		l.Close()
		if !bytes.Contains(buf.Bytes(), []byte(`"resource":"[redacted]"`)) {
			t.Fatal(buf.String())
		}
	})
}

func mustMCPMarkerTestContext(t *testing.T, resource string) LogContext {
	t.Helper()
	ctx, err := NewMCPLogContext("MCP", resource, "")
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}
