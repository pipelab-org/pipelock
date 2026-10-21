// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
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

func TestReverseHeaderSuppressionDestination(t *testing.T) {
	for _, tc := range []struct {
		name, upstreamQuery, requestQuery, suppressQuery string
		wantStatus                                       int
	}{
		{"route", "", "", "", http.StatusOK},
		{"request query", "", "mode=refresh", "", http.StatusForbidden},
		{"configured query", "fixed=1", "", "[?]fixed=1", http.StatusOK},
		{"combined query", "fixed=1", "mode=refresh", "[?]fixed=1", http.StatusForbidden},
		{"complete request query", "", "mode=refresh", "[?]mode=refresh", http.StatusOK},
		{"complete combined query", "fixed=1", "mode=refresh", "[?]fixed=1&mode=refresh", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := reverseTestConfig()
			cfg.RequestBodyScanning.ScanHeaders = true
			cfg.RequestBodyScanning.HeaderMode = "all"
			var reached atomic.Bool
			proxy, handler := reverseTestSetupWithHandler(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				reached.Store(true)
				w.WriteHeader(http.StatusOK)
			})
			handler.upstream.RawQuery = tc.upstreamQuery
			cfg.Suppress = []config.SuppressEntry{{
				Rule:   "Anthropic API Key",
				Path:   handler.upstream.Scheme + "://" + handler.upstream.Host + "/api/data" + tc.suppressQuery,
				Reason: "approved destination",
			}}
			target := proxy.URL + "/api/data"
			if tc.requestQuery != "" {
				target += "?" + tc.requestQuery
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer sk-"+"ant-"+strings.Repeat("a", 24))
			resp, err := proxy.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, tc.wantStatus, body)
			}
			if reached.Load() != (tc.wantStatus == http.StatusOK) {
				t.Fatalf("upstream reached=%v status=%d", reached.Load(), resp.StatusCode)
			}
			if tc.wantStatus == http.StatusForbidden && !strings.Contains(string(body), "header DLP: Anthropic API Key") {
				t.Fatalf("expected header DLP block, got %s", body)
			}
		})
	}
}
