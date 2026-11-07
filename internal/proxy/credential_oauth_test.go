// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestAnthropicOAuthBodyCarrier(t *testing.T) {
	key := "sk-" + "ant-ort01-" + strings.Repeat("a", 32)
	auth := func(extra string) string {
		return `{"grant_type":"refresh_token","refresh_token":"` + key + `","client_id":"client"` + extra + `}`
	}
	const target = "https://platform.claude.com/v1/oauth/token"
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name, body, target, method, media, surface string
		allow                                      bool
	}{
		{name: "refresh", body: auth(""), allow: true},
		{name: "revocation", body: `{"token_type_hint":"refresh_token","token":"` + key + `"}`, target: target + "/revoke", allow: true},
		{name: "copy", body: auth(`,"extra":"` + key + `"`)},
		{name: "encoded copy", body: auth(`,"extra":"` + base64.StdEncoding.EncodeToString([]byte(key)) + `"`)},
		{name: "split copy", body: auth(fmt.Sprintf(`,"extra":[%q,%q]`, key[:12], key[12:]))},
		{name: "different secret", body: auth(`,"extra":"AKIA` + strings.Repeat("B", 16) + `"`)},
		{name: "wrong field", body: `{"grant_type":"refresh_token","other":"` + key + `"}`},
		{name: "wrong grant", body: strings.Replace(auth(""), "refresh_token", "authorization_code", 1)},
		{name: "duplicate", body: auth(`,"refresh_token":"ordinary"`)},
		{name: "escaped duplicate", body: auth(`,"refresh_\u0074oken":"ordinary"`)},
		{name: "nested duplicate", body: auth(`,"other":{"x":1,"x":2}`)},
		{name: "malformed", body: auth("") + "{}"},
		{name: "array token", body: `{"grant_type":"refresh_token","refresh_token":["` + key + `"]}`},
		{name: "embedded token", body: strings.Replace(auth(""), key, "prefix "+key, 1)},
		{name: "third party", body: auth(""), target: "https://api.vendor.example/v1/oauth/token"},
		{name: "wrong Anthropic host", body: auth(""), target: "https://api.anthropic.com/v1/oauth/token"},
		{name: "wrong path", body: auth(""), target: target + "/extra"},
		{name: "escaped path", body: auth(""), target: "https://platform.claude.com/v1/oauth%2ftoken"},
		{name: "path traversal", body: auth(""), target: "https://platform.claude.com/v1/../v1/oauth/token"},
		{name: "query", body: auth(""), target: target + "?extra=1"},
		{name: "empty query", body: auth(""), target: target + "?"},
		{name: "GET", body: auth(""), method: http.MethodGet},
		{name: "plain text", body: auth(""), media: "text/plain"},
		{name: "websocket", body: auth(""), surface: "websocket_frame"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest, method, media := tc.target, tc.method, tc.media
			if dest == "" {
				dest = target
			}
			if method == "" {
				method = http.MethodPost
			}
			if media == "" {
				media = "application/json"
			}
			var allows []scanner.CredentialAudienceAllow
			buf, result := scanRequestBody(t.Context(), BodyScanRequest{
				Body: strings.NewReader(tc.body), Method: method, ContentType: media, MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes,
				Scanner: sc, Target: dest, AudienceSurface: tc.surface, Action: config.ActionBlock,
				OnCredentialAudienceAllow: func(a scanner.CredentialAudienceAllow) error { allows = append(allows, a); return nil },
			})
			if result.Clean != tc.allow {
				t.Fatalf("clean=%t want=%t result=%+v", result.Clean, tc.allow, result)
			}
			if tc.allow {
				if string(buf) != tc.body || len(allows) != 1 || allows[0].Surface != "body" {
					t.Fatalf("forwarded body or receipt changed: allows=%v", allows)
				}
			} else if len(allows) != 0 {
				t.Fatal("blocked request recorded as allowed")
			}
		})
	}
}

func TestAnthropicClientFetchAndForwardURLCarriers(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()
	key := "sk-" + "ant-oat01-" + strings.Repeat("a", 32)
	for _, target := range []string{
		"https://api.anthropic.com/api/claude_code/settings",
		"https://platform.claude.com/v1/oauth/token",
		"https://mcp-proxy.anthropic.com/v1/mcp/server-id",
	} {
		destination := target + "?value=" + key
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(destination), nil)
		rr := httptest.NewRecorder()
		p.handleFetch(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("fetch status=%d", rr.Code)
		}
		req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, destination, nil)
		rr = httptest.NewRecorder()
		p.handleForwardHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("forward status=%d", rr.Code)
		}
	}
}

func TestAnthropicOAuthBodyRedactionAndReceipt(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	key := "sk-" + "ant-ort01-" + strings.Repeat("a", 32)
	body := `{"grant_type":"refresh_token","refresh_token":"` + key + `"}`
	receiptErr := errors.New("receipt unavailable")
	for _, redaction := range []bool{false, true} {
		req := BodyScanRequest{
			Body: strings.NewReader(body), Method: http.MethodPost, ContentType: "application/json",
			MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc,
			Target: "https://platform.claude.com/v1/oauth/token", Action: config.ActionBlock,
			OnCredentialAudienceAllow: func(scanner.CredentialAudienceAllow) error { return receiptErr },
		}
		if redaction {
			req.RedactMatcher = redact.NewDefaultMatcher()
		}
		buf, result := scanRequestBody(t.Context(), req)
		if !result.Clean {
			t.Fatalf("redaction=%t result=%+v", redaction, result)
		}
		if redaction {
			if strings.Contains(string(buf), key) || result.CredentialAudienceReceiptErr != nil {
				t.Fatal("redacted credential earned delivery receipt")
			}
		} else if !errors.Is(result.CredentialAudienceReceiptErr, receiptErr) {
			t.Fatal("missing receipt error")
		}

	}
}

func TestAnthropicOAuthBodyReceiptWarnings(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	key := "sk-" + "ant-ort01-" + strings.Repeat("a", 32)
	body := fmt.Sprintf("{\"grant_type\":\"refresh_token\",\"refresh_token\":%q,\"extra\":%q}", key, opaqueHighEntropyBodyValue())
	receiptErr := errors.New("receipt unavailable")
	for _, action := range []string{config.ActionWarn, config.ActionBlock} {
		t.Run(action, func(t *testing.T) {
			calls := 0
			req := BodyScanRequest{
				Body: strings.NewReader(body), Method: http.MethodPost, ContentType: "application/json",
				MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc,
				Target: "https://platform.claude.com/v1/oauth/token", Action: config.ActionBlock,
				OnCredentialAudienceAllow: func(scanner.CredentialAudienceAllow) error {
					calls++
					return receiptErr
				},
			}
			applyContentEntropyConfig(&req, cfg)
			req.ContentEntropyEnabled = true
			req.ContentEntropyAction = action
			_, result := scanRequestBody(t.Context(), req)
			if result.Clean || result.EntropyFinding == nil || result.Action != action {
				t.Fatalf("expected entropy %s, got %+v", action, result)
			}
			// Only a clean body records an audience allow; a warning or block
			// result records none, so no receipt can claim delivery for it.
			if calls != 0 || result.CredentialAudienceReceiptErr != nil {
				t.Fatalf("%s body earned an audience allow: calls=%d err=%v", action, calls, result.CredentialAudienceReceiptErr)
			}
		})
	}
}

// A real refresh token is long and random. The designated credential field
// must not trip content entropy, while other high-entropy fields still do.
func TestAnthropicOAuthBodyEntropyExcludesCredential(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var b strings.Builder
	for i := 0; i < 80; i++ {
		b.WriteByte(alphabet[(i*37+11)%len(alphabet)])
	}
	key := "sk-" + "ant-ort01-" + b.String()
	for _, tc := range []struct {
		name        string
		extra       bool
		wantEntropy bool
	}{
		{name: "credential only"},
		{name: "other random field still scored", extra: true, wantEntropy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf("{\"grant_type\":\"refresh_token\",\"refresh_token\":%q}", key)
			if tc.extra {
				body = strings.TrimSuffix(body, "}") + fmt.Sprintf(",\"extra\":%q}", opaqueHighEntropyBodyValue())
			}
			req := BodyScanRequest{
				Body: strings.NewReader(body), Method: http.MethodPost, ContentType: "application/json",
				MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc,
				Target: "https://platform.claude.com/v1/oauth/token", Action: config.ActionBlock,
			}
			applyContentEntropyConfig(&req, cfg)
			req.ContentEntropyEnabled = true
			req.ContentEntropyAction = config.ActionBlock
			_, result := scanRequestBody(t.Context(), req)
			if (result.EntropyFinding != nil) != tc.wantEntropy {
				t.Fatalf("entropy finding = %v, want %v", result.EntropyFinding != nil, tc.wantEntropy)
			}
			if !tc.wantEntropy && !result.Clean {
				t.Fatalf("refresh body with a real-shaped token was not clean: %+v", result)
			}
		})
	}
}

func TestAnthropicOAuthBodyTransports(t *testing.T) {
	const host = "platform.claude.com"
	const endpoint = "https://" + host + "/v1/oauth/token"
	key := "sk-" + "ant-ort01-" + strings.Repeat("a", 32)
	for _, transport := range []string{TransportForward, "intercept", TransportReverse} {
		for _, tc := range []struct {
			name, query           string
			warning, receiptFails bool
			wantStatus            int
		}{
			{name: "allowed", wantStatus: http.StatusOK},
			{name: "empty query", query: "?", wantStatus: http.StatusForbidden},
			{name: "query", query: "?extra=1", wantStatus: http.StatusForbidden},
			{name: "receipt failure", receiptFails: true, wantStatus: http.StatusForbidden},
			// A warning result delivers without an audience allow, as on main.
			{name: "warning allowed", warning: true, wantStatus: http.StatusOK},
		} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				cfg := testScannerConfig()
				cfg.ResponseScanning.Enabled = false
				cfg.FlightRecorder.RequireReceipts = true
				cfg.RequestBodyScanning.ContentEntropyEnabled = true
				cfg.RequestBodyScanning.ContentEntropyAction = config.ActionWarn
				cfg.DNS.HostOverrides = map[string][]string{host: {"93.184.216.34"}}
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				p, err := New(cfg, audit.NewNop(), sc, metrics.New())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				var rejected atomic.Int32
				rph := newReceiptProxyHelperWithRedactor(t, p.metrics, func(_ context.Context, text string) scanner.TextDLPResult {
					if tc.receiptFails && strings.Contains(text, credentialAudienceReceiptExtensionKey) {
						rejected.Add(1)
						return scanner.TextDLPResult{Incomplete: true}
					}
					return scanner.TextDLPResult{Clean: true}
				})
				t.Cleanup(func() { _ = rph.rec.Close() })
				p.receiptEmitterPtr.Store(rph.emitter)
				// Generic admission evidence succeeds; only audience evidence fails.
				if err := p.emitAllowPathReceipt(cfg, receipt.EmitOpts{
					ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
					Layer: "proxy", Transport: transport, Method: http.MethodPost, Target: endpoint,
				}); err != nil {
					t.Fatalf("generic admission receipt: %v", err)
				}
				body := fmt.Sprintf("{\"grant_type\":\"refresh_token\",\"refresh_token\":%q}", key)
				if tc.warning {
					body = strings.TrimSuffix(body, "}") + fmt.Sprintf(",\"extra\":%q}", opaqueHighEntropyBodyValue())
				}
				var hits atomic.Int32
				rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					hits.Add(1)
					got, readErr := io.ReadAll(r.Body)
					if readErr != nil || string(got) != body {
						t.Errorf("upstream body changed: %v", readErr)
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
				})
				p.client.Transport = rt
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, endpoint+tc.query, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				switch transport {
				case TransportForward:
					p.handleForwardHTTP(w, req)
				case "intercept":
					// The decrypted request enters in origin form.
					req.URL.Scheme, req.URL.Host = "", ""
					newInterceptHandler(&InterceptContext{
						TargetHost: host, TargetPort: "443", Config: cfg, Scanner: sc,
						Logger: p.logger, Metrics: p.metrics, Proxy: p,
					}, rt).ServeHTTP(w, req)
				case TransportReverse:
					upstream, parseErr := url.Parse("https://" + host)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					rp := NewReverseProxy(upstream, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
					rp.receiptEmitterPtr = &p.receiptEmitterPtr
					rp.proxy.Transport = rt
					rp.ServeHTTP(w, req)
				}
				wantHits := int32(0)
				if tc.wantStatus == http.StatusOK {
					wantHits = 1
				}
				if w.Code != tc.wantStatus || hits.Load() != wantHits {
					t.Fatalf("status/hits=%d/%d want=%d/%d; %s", w.Code, hits.Load(), tc.wantStatus, wantHits, w.Body.String())
				}
				if tc.receiptFails {
					if rejected.Load() == 0 || w.Header().Get(blockreason.HeaderLayer) != blockLayerCredentialAudienceReceipt {
						t.Fatalf("audience receipt failure not enforced: rejected=%d layer=%s", rejected.Load(), w.Header().Get(blockreason.HeaderLayer))
					}
				}
				allows := 0
				for _, r := range rph.findReceipts(t) {
					if r.ActionRecord.Layer == credentialAudienceReceiptExtensionKey {
						allows++
					}
				}
				wantAllows := int(wantHits)
				if tc.warning {
					wantAllows = 0
				}
				if allows != wantAllows {
					t.Fatalf("audience receipts=%d want=%d", allows, wantAllows)
				}
			})
		}
	}
}
