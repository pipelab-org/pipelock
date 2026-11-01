// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMCPResourceURLLengthDefault(t *testing.T) {
	sc := testInputScanner(t)
	for _, tc := range []struct {
		name string
		size int
		tail string
		want bool
	}{
		{"browser URL", 2200, "", true},
		{"RFC limit", 8000, "", true},
		{"oversize", 8001, "", false},
		{"credential beyond old limit", 2400, "/ghp_" + strings.Repeat("A", 36), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const base = "https://api.vendor.example/"
			target := base + strings.Repeat("a", tc.size-len(base)-len(tc.tail)) + tc.tail
			line := makeRequest(1, "resources/read", map[string]string{"uri": target})
			got := ScanRequest(t.Context(), []byte(line), sc, config.ActionBlock, config.ActionBlock)
			if got.Clean != tc.want {
				t.Fatalf("clean=%v, want %v: %+v", got.Clean, tc.want, got)
			}
		})
	}
}

func TestToolArgumentLongURLDLP(t *testing.T) {
	sc := testInputScanner(t)
	for _, credential := range []bool{false, true} {
		target := "https://api.vendor.example/" + strings.Repeat("a", 2200)
		if credential {
			target += "/ghp_" + strings.Repeat("A", 36)
		}
		line := makeRequest(1, "tools/call", map[string]any{
			"name": "fetch", "arguments": map[string]string{"url": target},
		})
		got := ScanRequest(t.Context(), []byte(line), sc, config.ActionBlock, config.ActionBlock)
		if got.Clean == credential {
			t.Fatalf("credential=%v: %+v", credential, got)
		}
	}
}
