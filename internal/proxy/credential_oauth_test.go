// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
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
