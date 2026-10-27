// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWithScanRouteAttributesResponseScan(t *testing.T) {
	const (
		transport = "mcp_stdio"
		server    = "files"
	)
	tests := []struct {
		name      string
		ctxAgent  string
		routeAgnt string
		wantAgent string
	}{
		{name: "fills missing agent", routeAgnt: "route-agent", wantAgent: "route-agent"},
		{name: "keeps request agent", ctxAgent: "request-agent", routeAgnt: "route-agent", wantAgent: "request-agent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger, err := New("json", "custom", "", true, true)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			logger.zl = logger.zl.Output(&buf)

			base, err := NewHTTPLogContext("GET", "https://api.vendor.example/data?token=x", "10.0.0.1", "req-7", tt.ctxAgent)
			if err != nil {
				t.Fatalf("NewHTTPLogContext: %v", err)
			}
			ctx := base.WithScanRoute(transport, server, tt.routeAgnt)
			if base.scanTransport != "" || base.mcpServer != "" {
				t.Fatal("WithScanRoute mutated its receiver")
			}
			logger.LogResponseScan(ctx, "warn", 1, []string{"Prompt Injection"}, nil)

			var entry map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &entry); err != nil {
				t.Fatalf("parse log entry: %v\nraw: %s", err, buf.String())
			}
			for key, want := range map[string]string{
				"transport":  transport,
				"mcp_server": server,
				"agent":      tt.wantAgent,
				"url":        "https://api.vendor.example/[redacted]",
			} {
				if got, _ := entry[key].(string); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			if strings.Contains(buf.String(), "token=x") {
				t.Errorf("response-scan URL was not redacted: %s", buf.String())
			}
		})
	}
}
