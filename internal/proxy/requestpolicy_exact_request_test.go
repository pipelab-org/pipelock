// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func exactRequestRule(target, body string) config.RequestPolicyRule {
	u, _ := url.Parse(target)
	digest := sha256.Sum256([]byte(body))
	return config.RequestPolicyRule{
		Name: "block-sharing", Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{u.Hostname()}, Methods: []string{http.MethodPost, http.MethodPatch}, PathPrefixes: []string{"/items/"}},
		Except: &config.RequestPolicyException{Requests: []config.RequestPolicyExactRequest{{URL: target, Method: http.MethodPost, BodySHA256: hex.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Owner: "operator", Reason: "approved named users"}}},
	}
}

func TestRequestPolicyExactRequest(t *testing.T) {
	const target = "https://api.example.com/items/1/invite"
	const body = `{"sendInvitation":false,"requireSignIn":true,"roles":["read"],"recipients":[{"email":"person@vendor.example"}]}`
	rule := exactRequestRule(target, body)
	cfg := reqPolicyConfig(rule)
	cfg.RequestPolicy.OnParseError = config.ActionAllow
	cfg.RequestPolicy.OnOpaqueOperation = config.ActionWarn
	p := newTestProxyWithConfig(t, cfg)
	base := requestPolicyInput{Host: rpTestHost, Method: http.MethodPost, Path: "/items/1/invite", ContentType: "application/json", Body: []byte(body), BodyRead: true, Target: target}
	for _, tc := range []struct {
		name  string
		edit  func(*requestPolicyInput)
		block bool
	}{
		{"approved", func(*requestPolicyInput) {}, false},
		{"notification", func(r *requestPolicyInput) {
			r.Body = []byte(strings.ReplaceAll(body, `"sendInvitation":false`, `"sendInvitation":true`))
		}, true},
		{"role", func(r *requestPolicyInput) { r.Body = []byte(strings.ReplaceAll(body, `"read"`, `"write"`)) }, true},
		{"recipient", func(r *requestPolicyInput) { r.Body = []byte(strings.ReplaceAll(body, "person@", "other@")) }, true},
		{"query", func(r *requestPolicyInput) { r.Query = "extra=true"; r.Target += "?extra=true" }, true},
		{"sibling", func(r *requestPolicyInput) {
			r.Path = "/items/2/invite"
			r.Target = strings.ReplaceAll(target, "/1/", "/2/")
		}, true},
		{"whitespace", func(r *requestPolicyInput) { r.Body = append([]byte(" "), r.Body...) }, true},
		{"content type", func(r *requestPolicyInput) { r.ContentType = "text/plain" }, true},
		{"inconsistent query", func(r *requestPolicyInput) { r.Query = "extra=true" }, true},
		{"unread", func(r *requestPolicyInput) { r.BodyRead = false }, true},
		{"malformed", func(r *requestPolicyInput) { r.Body = []byte("{") }, true},
		{"method", func(r *requestPolicyInput) { r.Method = http.MethodPatch }, true},
		{"override", func(r *requestPolicyInput) {
			r.Headers = http.Header{"X-Http-Method-Override": []string{http.MethodPost}}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.edit(&in)
			if got := p.applyRequestPolicy(in).Block; got != tc.block {
				t.Fatalf("block=%v want=%v", got, tc.block)
			}
		})
	}
	// An operator cannot approve ambiguous JSON by supplying its digest.
	ambiguous := `{"recipients":[{"email":"a@vendor.example","email":"b@vendor.example"}]}`
	p = newTestProxyWithConfig(t, reqPolicyConfig(exactRequestRule(target, ambiguous)))
	base.Body = []byte(ambiguous)
	if !p.applyRequestPolicy(base).Block {
		t.Fatal("approved duplicate JSON forwarded")
	}
}

func TestInterceptExactRequest(t *testing.T) {
	h := newWebPlatformHarness(t)
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(upstream.Close)
	const body = `{"sendInvitation":false,"roles":["read"]}`
	const path = "/items/1/invite"
	h.cfg.RequestPolicy = config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{exactRequestRule(upstream.URL+path, body)}}
	if err := h.p.setupRequestPolicy(h.cfg); err != nil {
		t.Fatal(err)
	}
	if got := h.send(upstream, http.MethodPost, path, "exact-reader", "application/json", body); got != http.StatusNoContent {
		t.Fatalf("approved HTTP=%d", got)
	}
	if got := h.send(upstream, http.MethodPost, path, "exact-reader", "application/json", strings.ReplaceAll(body, "false", "true")); got != http.StatusForbidden {
		t.Fatalf("changed HTTP=%d", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls=%d want=1", calls.Load())
	}
	// Revocation replaces the matcher; the previously approved body must fail.
	h.cfg.RequestPolicy.Rules[0].Except = nil
	if err := h.p.setupRequestPolicy(h.cfg); err != nil {
		t.Fatal(err)
	}
	if got := h.send(upstream, http.MethodPost, path, "exact-reader", "application/json", body); got != http.StatusForbidden {
		t.Fatalf("revoked HTTP=%d", got)
	}
}

func TestForwardExactRequest(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(upstream.Close)
	const body = `{"sendInvitation":false}`
	const path = "/items/1/invite"
	p := newTestProxyWithConfig(t, reqPolicyConfig(exactRequestRule(upstream.URL+path, body)))
	p.client.Transport = upstream.Client().Transport
	handler := p.buildHandler(p.buildMux())
	for _, tc := range []struct {
		body   string
		status int
	}{{body, http.StatusNoContent}, {`{"sendInvitation":true}`, http.StatusForbidden}} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL+path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("forward HTTP=%d want=%d", w.Code, tc.status)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls=%d want=1", calls.Load())
	}
}

// An intercepted tunnel spells every target host:port, so an approval written
// without the default port must still match, while another port must not.
func TestRequestPolicyExactRequestCanonicalTarget(t *testing.T) {
	const body = `{"sendInvitation":false}`
	const path = "/items/1/invite"
	for _, tc := range []struct {
		name, approved, target string
		block                  bool
	}{
		{"default port elided in approval", "https://" + rpTestHost + path, "https://" + rpTestHost + ":443" + path, false},
		{"default port in approval", "https://" + rpTestHost + ":443" + path, "https://" + rpTestHost + path, false},
		{"uppercase host in approval", "https://" + strings.ToUpper(rpTestHost) + path, "https://" + rpTestHost + ":443" + path, false},
		{"other port", "https://" + rpTestHost + path, "https://" + rpTestHost + ":8443" + path, true},
		{"approved other port", "https://" + rpTestHost + ":8443" + path, "https://" + rpTestHost + ":443" + path, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProxyWithConfig(t, reqPolicyConfig(exactRequestRule(tc.approved, body)))
			in := requestPolicyInput{Host: rpTestHost, Method: http.MethodPost, Path: path, ContentType: "application/json", Body: []byte(body), BodyRead: true, Target: tc.target}
			if got := p.applyRequestPolicy(in).Block; got != tc.block {
				t.Fatalf("block=%v want=%v", got, tc.block)
			}
		})
	}
}
