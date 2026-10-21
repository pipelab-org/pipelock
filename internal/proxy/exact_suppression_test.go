// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const exactSuppressTarget = "https://api.vendor.example/v1/oauth/token"

func TestExactURLSuppressionRequestBoundaries(t *testing.T) {
	// Load a validated rule so request-body and header consumers use the same
	// entry as the configuration matcher.
	cfg, err := config.LoadBytes([]byte("suppress:\n  - rule: Anthropic API Key\n    path: " + exactSuppressTarget + "\n    reason: Operator-approved token route\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Internal = nil
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.ApplyDefaults()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	key := "sk-" + "ant-" + strings.Repeat("a", 24)
	for _, tc := range []struct {
		name, target, field, value string
		wantClean                  bool
	}{
		{"exact", exactSuppressTarget, "refresh_token", key, true},
		{"explicit standard port", "https://api.vendor.example:443/v1/oauth/token", "refresh_token", key, true},
		{"another field is also suppressed", exactSuppressTarget, "note", key, true},
		{"other route", "https://api.vendor.example/v1/other", "refresh_token", key, false},
		{"other port", "https://api.vendor.example:8443/v1/oauth/token", "refresh_token", key, false},
		{"query target", exactSuppressTarget + "?mode=refresh", "refresh_token", key, false},
		{"lookalike", "https://api.vendor.example.attacker.example/v1/oauth/token", "refresh_token", key, false},
		// The target is agent-chosen, so a foreign URL that merely ends with
		// (or embeds) the approved URL must not inherit the exact entry.
		{"foreign host path ends with approved URL", "https://attacker.example/" + exactSuppressTarget, "refresh_token", key, false},
		{"approved route nested under another route", "https://api.vendor.example/v1/other/" + exactSuppressTarget, "refresh_token", key, false},
		{"query ends with approved URL", exactSuppressTarget + "?next=" + exactSuppressTarget, "refresh_token", key, false},
		{"core sibling", exactSuppressTarget, "note", key + " " + "AKIA" + strings.Repeat("B", 16), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, body := scanRequestBody(t.Context(), BodyScanRequest{
				Body: strings.NewReader(`{"` + tc.field + `":"` + tc.value + `"}`), ContentType: "application/json",
				MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc, Target: tc.target,
				Action: config.ActionBlock, Suppress: cfg.Suppress,
			})
			header := scanRequestHeadersForTarget(t.Context(), http.Header{"Authorization": []string{"Bearer " + tc.value}}, cfg, sc, tc.target)
			for name, result := range map[string]*BodyScanResult{"body": &body, "header": header} {
				clean := result == nil || result.Clean
				if clean != tc.wantClean || (!clean && result.Action != config.ActionBlock) {
					t.Fatalf("%s clean=%v result=%+v", name, clean, result)
				}
			}
		})
	}
	urlResult := sc.Scan(t.Context(), exactSuppressTarget+"?credential="+key)
	if urlResult.Allowed {
		t.Fatal("body/header suppression silenced URL DLP")
	}
}
