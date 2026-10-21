// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const audienceDiagnosticTarget = "https://api.vendor.example/v1/oauth/token"

func TestCredentialAudienceDiagnosticsSurvivingFindings(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	key := "sk-" + "ant-" + strings.Repeat("a", 24)
	for _, action := range []string{config.ActionBlock, config.ActionWarn} {
		t.Run(action, func(t *testing.T) {
			cfg := cfg.Clone()
			cfg.RequestBodyScanning.Action = action
			for _, target := range []string{audienceDiagnosticTarget, "", "/unowned", "https://api.anthropic.com/v1/messages"} {
				wantMismatch := target == audienceDiagnosticTarget
				_, body := scanRequestBody(t.Context(), BodyScanRequest{
					Body: strings.NewReader(`{"refresh_token":"` + key + `"}`), ContentType: "application/json",
					MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc, Target: target, Action: action,
				})
				header := scanRequestHeadersForTarget(t.Context(), http.Header{"Authorization": []string{"Bearer " + key}}, cfg, sc, target)
				for name, result := range map[string]*BodyScanResult{"body": &body, "header": header} {
					if target == "https://api.anthropic.com/v1/messages" {
						if result != nil && (!result.Clean || len(result.CredentialAudienceMismatches) != 0) {
							t.Fatalf("%s audience allow changed: %+v", name, result)
						}
						continue
					}
					if result == nil || result.Clean || result.Action != action || result.Reason != "" {
						t.Fatalf("%s verdict changed: %+v", name, result)
					}
					if got := len(result.CredentialAudienceMismatches) > 0; got != wantMismatch {
						t.Fatalf("%s target %q mismatch = %+v", name, target, result.CredentialAudienceMismatches)
					}
					if wantMismatch {
						mismatch := result.CredentialAudienceMismatches[0]
						if mismatch.PatternName != "Anthropic API Key" || mismatch.Surface != name || mismatch.Destination != "api.vendor.example" {
							t.Fatalf("%s diagnosis = %+v", name, mismatch)
						}
						if explanation := result.withAudienceExplanation("blocked"); !strings.Contains(explanation, "credential audience mismatch") || strings.Contains(explanation, key) {
							t.Fatalf("%s explanation = %q", name, explanation)
						}
					}
				}
			}
		})
	}
}

func TestCredentialAudienceDiagnosticsExactRouteSuppression(t *testing.T) {
	// Loading the guide's YAML proves the existing control is accepted by
	// config validation, rather than merely exercising a hand-built entry.
	cfg, err := config.LoadBytes([]byte("suppress:\n  - rule: Anthropic API Key\n    path: " + audienceDiagnosticTarget + "\n    reason: Operator-approved token route\n"))
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
		{"exact", audienceDiagnosticTarget, "refresh_token", key, true},
		{"explicit standard port", "https://api.vendor.example:443/v1/oauth/token", "refresh_token", key, true},
		{"another field is also suppressed", audienceDiagnosticTarget, "note", key, true},
		{"other route", "https://api.vendor.example/v1/other", "refresh_token", key, false},
		{"other port", "https://api.vendor.example:8443/v1/oauth/token", "refresh_token", key, false},
		{"query target", audienceDiagnosticTarget + "?mode=refresh", "refresh_token", key, false},
		{"lookalike", "https://api.vendor.example.attacker.example/v1/oauth/token", "refresh_token", key, false},
		{"core sibling", audienceDiagnosticTarget, "note", key + " " + "AKIA" + strings.Repeat("B", 16), false},
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
				if result != nil && (tc.wantClean || tc.name == "core sibling") && len(result.CredentialAudienceMismatches) != 0 {
					t.Fatalf("%s explained a suppressed finding: %+v", name, result)
				}
			}
		})
	}
	urlResult := sc.Scan(t.Context(), audienceDiagnosticTarget+"?credential="+key)
	if urlResult.Allowed {
		t.Fatal("body/header suppression silenced URL DLP")
	}
}

func TestForwardProxyCredentialAudienceDiagnosticResponse(t *testing.T) {
	for _, surface := range []string{"body", "header"} {
		t.Run(surface, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamCalls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(upstream.Close)
			upstreamURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			cfg := testScannerConfig()
			cfg.DLP.GitHubEnterpriseHosts = []string{"ghe.corp.example"}
			cfg.DLP.GitLabHosts = []string{"gitlab.corp.example"}
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			key := "ghp_" + strings.Repeat("a", 36)
			body := "benign"
			if surface == "body" {
				body = key
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL+"/v1/oauth/token", strings.NewReader(body))
			req.Header.Set("Content-Type", "text/plain")
			if surface == "header" {
				req.Header.Set("Authorization", "Bearer "+key)
			}
			rec := httptest.NewRecorder()
			p.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "credential audience mismatch") || !strings.Contains(rec.Body.String(), upstreamURL.Hostname()) || strings.Contains(rec.Body.String(), key) {
				t.Fatalf("status=%d response=%s", rec.Code, rec.Body.String())
			}
			if got := upstreamCalls.Load(); got != 0 {
				t.Fatalf("blocked request reached upstream %d times", got)
			}
			for _, private := range []string{"ghe.corp.example", "gitlab.corp.example"} {
				if strings.Contains(rec.Body.String(), private) {
					t.Fatal("response disclosed an operator-declared audience host")
				}
			}
			if !strings.Contains(rec.Body.String(), "immutable core rule, suppress does not apply") {
				t.Fatalf("core rule remedy missing: %s", rec.Body.String())
			}
		})
	}
}

func TestReverseProxyCredentialAudienceDiagnosticResponse(t *testing.T) {
	for _, surface := range []string{"body", "header", "url"} {
		t.Run(surface, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamCalls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(upstream.Close)
			upstreamURL, err := url.Parse(upstream.URL + "/joined")
			if err != nil {
				t.Fatal(err)
			}
			cfg := reverseTestConfig()
			cfg.RequestBodyScanning.ScanHeaders = true
			cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			var cfgPtr atomic.Pointer[config.Config]
			var scPtr atomic.Pointer[scanner.Scanner]
			cfgPtr.Store(cfg)
			scPtr.Store(sc)
			var auditLog bytes.Buffer
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &auditLog)
			if err != nil {
				t.Fatal(err)
			}
			rp := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, metrics.New(), killswitch.New(cfg), nil, nil)
			key := "sk-" + "ant-" + strings.Repeat("a", 24)
			body := "benign"
			if surface == "body" {
				body = key
			}
			target := "http://inbound.example/v1"
			if surface == "url" {
				target += "/" + key
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(body))
			req.Header.Set("Content-Type", "text/plain")
			if surface == "header" {
				req.Header.Set("Authorization", "Bearer "+key)
			}
			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "credential audience mismatch") || !strings.Contains(rec.Body.String(), "127.0.0.1") || strings.Contains(rec.Body.String(), "inbound.example") || strings.Contains(rec.Body.String(), key) {
				t.Fatalf("status=%d response=%s", rec.Code, rec.Body.String())
			}
			if got := upstreamCalls.Load(); got != 0 {
				t.Fatalf("blocked request reached upstream %d times", got)
			}
			if surface == "url" {
				var entry struct {
					Event string `json:"event"`
					Hint  string `json:"remediation_hint"`
				}
				if err := json.NewDecoder(&auditLog).Decode(&entry); err != nil {
					t.Fatal(err)
				}
				if entry.Event != "body_dlp" || !strings.Contains(entry.Hint, "Remove the credential from the request URL") || !strings.Contains(entry.Hint, "does not consult") {
					t.Fatalf("reverse URL audit event=%+v", entry)
				}
			}
		})
	}
}

func TestWebSocketCredentialAudienceDiagnostic(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	key := "sk-" + "ant-" + strings.Repeat("a", 24)
	blocked, hard, action, reason, err := p.dlpScanWSHeaders(t.Context(), http.Header{"Authorization": []string{"Bearer " + key}}, sc, cfg, "wss://api.vendor.example/v1", audit.LogContext{})
	if !blocked || !hard || action != config.ActionBlock || err != nil || !strings.Contains(reason, "credential audience mismatch") || strings.Contains(reason, key) {
		t.Fatalf("blocked=%v hard=%v action=%s reason=%s err=%v", blocked, hard, action, reason, err)
	}
	blocked, _, _, reason, err = p.dlpScanWSHeaders(t.Context(), http.Header{"Authorization": []string{"Bearer " + key}}, sc, cfg, "wss://api.anthropic.com/v1", audit.LogContext{})
	if blocked || err != nil || reason != "" {
		t.Fatalf("audience header blocked=%v reason=%s err=%v", blocked, reason, err)
	}
	relay := newCredentialAudienceWebSocketRelay(sc, cfg, "wss://api.vendor.example/v1")
	_, result := relay.scanClientMessageBody(t.Context(), []byte(`{"credential":"`+key+`"}`))
	if result.Clean || len(result.CredentialAudienceMismatches) != 1 || result.CredentialAudienceMismatches[0].Surface != "websocket_frame" {
		t.Fatalf("frame diagnostic = %+v", result)
	}
}

func TestWebSocketCredentialAudienceDiagnosticHandshake(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		name := "clean upgrade"
		if blocked {
			name = "credential rejected before upgrade"
		}
		t.Run(name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				conn, _, _, err := ws.UpgradeHTTP(r, w)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte(testWSHello))
			}))
			t.Cleanup(upstream.Close)
			upstreamURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			proxyAddr, p, cleanup := setupWSProxyDefaultWithProxy(t, nil)
			t.Cleanup(p.Close)
			t.Cleanup(cleanup)
			if !blocked {
				conn, err := dialWSConn(proxyAddr, upstreamURL.Host)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close() }()
				if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				message, _, err := wsutil.ReadServerData(conn)
				if err != nil || string(message) != testWSHello || upstreamCalls.Load() != 1 {
					t.Fatalf("message=%q err=%v upstream calls=%d", message, err, upstreamCalls.Load())
				}
				return
			}
			key := "sk-" + "ant-" + strings.Repeat("a", 24)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+proxyAddr+"/ws?url="+url.QueryEscape("wss://"+upstreamURL.Host), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+key)
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set("Sec-WebSocket-Version", "13")
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Pipelock-Block-Reason") != string(blockreason.DLPMatch) ||
				!strings.Contains(string(body), "credential audience mismatch") || !strings.Contains(string(body), "surface header") ||
				!strings.Contains(string(body), upstreamURL.Hostname()) || strings.Contains(string(body), key) {
				t.Fatalf("status=%d headers=%v response=%s", resp.StatusCode, resp.Header, body)
			}
			if got := upstreamCalls.Load(); got != 0 {
				t.Fatalf("blocked handshake reached upstream %d times", got)
			}
		})
	}
}

func TestCheckRedirectHeaderBlockCarriesAudienceExplanation(t *testing.T) {
	p, cfg, sc := redirectPolicyTestProxy(t)
	redirectReq, originalReq := redirectPolicyRequests(t, cfg, sc)
	originalReq.URL.Host = "gitlab.com"
	token := fakeGitLabPAT()
	redirectReq.Header.Set("Private-Token", token)
	originalReq.Header.Set("Private-Token", token)
	err := p.client.CheckRedirect(redirectReq, []*http.Request{originalReq})
	blockedErr, ok := blockedRequestErrorFrom(err)
	if !ok || blockedErr.layer != "header_dlp" {
		t.Fatalf("redirect block = %v, want header_dlp", err)
	}
	msg := blockedErr.Error()
	if !strings.Contains(msg, "credential audience mismatch") || !strings.Contains(msg, "api.vendor.example") || strings.Contains(msg, token) {
		t.Fatalf("redirect header explanation = %q", msg)
	}
}
