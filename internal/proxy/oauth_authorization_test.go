// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const nativeOAuthProxyHost = "auth.vendor.example"

func nativeOAuthProxyURL() string {
	// Construct opaque synthetic values at runtime; no captured OAuth material.
	state := "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789"
	q := url.Values{"response_type": {"code"}, "client_id": {"native-client"}, "redirect_uri": {"http://127.0.0.1:49152/callback"}, "state": {state}, "nonce": {state}}
	return "https://" + nativeOAuthProxyHost + "/oauth/authorize?" + q.Encode()
}

func nativeOAuthProxyConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = nil
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	cfg.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = []config.OAuthAuthorizationEndpoint{{Host: nativeOAuthProxyHost, Path: "/oauth/authorize"}}
	return cfg
}

func TestNativeOAuthHTTPTransports(t *testing.T) {
	for _, surface := range []string{"fetch", "forward", "intercept"} {
		t.Run(surface, func(t *testing.T) {
			for _, tt := range []struct {
				name, method string
				grant        bool
				want         int
			}{
				{"approved GET", http.MethodGet, true, http.StatusOK},
				{"no grant", http.MethodGet, false, http.StatusForbidden},
				{"POST retains gates", http.MethodPost, true, http.StatusForbidden},
			} {
				// /fetch dispatches GET regardless of its front-door method.
				if surface == "fetch" && tt.method != http.MethodGet {
					continue
				}
				t.Run(tt.name, func(t *testing.T) {
					cfg := nativeOAuthProxyConfig()
					if !tt.grant {
						cfg.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = nil
					}
					var hits atomic.Int32
					backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						hits.Add(1)
						w.Header().Set("Content-Type", "text/plain")
						_, _ = io.WriteString(w, "authorization page")
					}))
					defer backend.Close()
					sc := scanner.MustNew(cfg)
					defer sc.Close()
					logger := audit.NewNop()
					m := metrics.New()
					rt := interceptRewriteRoundTripper{base: backend.Client().Transport, addr: backend.Listener.Addr().String()}
					target := nativeOAuthProxyURL()
					var status int
					if surface == "intercept" {
						cache, pool, _, unused, _, _ := testInterceptSetup(t)
						unused.Close()
						cfg.TLSInterception.Enabled = true
						req, err := http.NewRequestWithContext(t.Context(), tt.method, target, nil)
						if err != nil {
							t.Fatal(err)
						}
						resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{Upstream: backend, TargetHost: nativeOAuthProxyHost, TargetPort: "443", UpstreamRT: rt, Cache: cache, Pool: pool, Config: cfg, Scanner: sc, Logger: logger, Metrics: m, Request: req})
						status = resp.StatusCode
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
					} else {
						p, err := New(cfg, logger, sc, m)
						if err != nil {
							t.Fatal(err)
						}
						defer p.Close()
						p.client.Transport = rt
						endpoint := target
						if surface == "fetch" {
							endpoint = "http://proxy.vendor.example/fetch?url=" + url.QueryEscape(target)
						}
						req := httptest.NewRequestWithContext(t.Context(), tt.method, endpoint, nil)
						rec := httptest.NewRecorder()
						if surface == "fetch" {
							p.handleFetch(rec, req)
						} else {
							p.handleForwardHTTP(rec, req)
						}
						status = rec.Code
					}
					if status != tt.want {
						t.Fatalf("status=%d want=%d", status, tt.want)
					}
					if (hits.Load() > 0) != (tt.want == http.StatusOK) {
						t.Fatalf("upstream hits=%d for status=%d", hits.Load(), status)
					}
				})
			}
		})
	}
}

func TestNativeOAuthFetchRedirectAndReload(t *testing.T) {
	cfg := nativeOAuthProxyConfig()
	var hits atomic.Int32
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, nativeOAuthProxyURL(), http.StatusFound)
			return
		}
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "authorization page")
	}))
	defer backend.Close()
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.client.Transport = interceptRewriteRoundTripper{base: backend.Client().Transport, addr: backend.Listener.Addr().String()}
	fetch := func(target string) int {
		t.Helper()
		rec := httptest.NewRecorder()
		p.handleFetch(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.vendor.example/fetch?url="+url.QueryEscape(target), nil))
		return rec.Code
	}
	if got := fetch("https://" + nativeOAuthProxyHost + "/start"); got != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("redirect GET status=%d hits=%d", got, hits.Load())
	}
	for _, granted := range []bool{true, false, false, true} {
		next := nativeOAuthProxyConfig()
		if !granted {
			next.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = nil
		}
		if !p.Reload(next, scanner.MustNew(next)) {
			t.Fatal("reload failed")
		}
		got := fetch(nativeOAuthProxyURL())
		want := http.StatusForbidden
		if granted {
			want = http.StatusOK
		}
		if got != want {
			t.Fatalf("grant=%v status=%d want=%d", granted, got, want)
		}
	}
	// A grant for a URL carried in a fetch request is never authority to fetch
	// its loopback callback as a destination in its own right.
	if got := fetch("http://127.0.0.1:49152/callback?code=short"); got != http.StatusForbidden {
		t.Fatalf("direct callback status=%d", got)
	}
}

func TestNativeOAuthForwardRedirectMethodChange(t *testing.T) {
	cfg := nativeOAuthProxyConfig()
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// net/http changes POST to GET for this 302. The target's method must be
	// recomputed rather than inherited from the source request's scan context.
	p.client.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/start" {
			t.Fatal("forward redirect target was fetched")
		}
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {nativeOAuthProxyURL()}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	rec := httptest.NewRecorder()
	p.handleForwardHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://auth.vendor.example/start", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("redirect status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != nativeOAuthProxyURL() {
		t.Fatal("authorization redirect changed")
	}
}

func TestNativeOAuthExistingInterceptReload(t *testing.T) {
	cfg := nativeOAuthProxyConfig()
	sc := scanner.MustNew(cfg)
	// A CONNECT handler leases its scanner until the tunnel closes. Preserve that
	// exact state, so an old scanner being torn down cannot make this test pass.
	release, ok := sc.BeginUse()
	if !ok {
		t.Fatal("scanner lease unavailable")
	}
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		release()
		t.Fatal(err)
	}
	defer p.Close()
	defer release()
	var hits atomic.Int32
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		hits.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("authorization page")), Request: r}, nil
	})
	handler := newInterceptHandler(&InterceptContext{TargetHost: nativeOAuthProxyHost, TargetPort: "443", Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: p.metrics, Proxy: p}, rt)
	request := func(want int) {
		t.Helper()
		before := hits.Load()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, nativeOAuthProxyURL(), nil))
		if rec.Code != want {
			t.Fatalf("existing tunnel status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
		}
		if (hits.Load() > before) != (want == http.StatusOK) {
			t.Fatal("upstream dispatch disagrees with grant")
		}
	}
	request(http.StatusOK)
	unchanged := cfg.Clone()
	unchanged.FetchProxy.TimeoutSeconds++
	if !p.Reload(unchanged, scanner.MustNew(unchanged)) {
		t.Fatal("unrelated reload failed")
	}
	request(http.StatusOK)
	revoked := unchanged.Clone()
	revoked.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = nil
	if !p.Reload(revoked, scanner.MustNew(revoked)) {
		t.Fatal("revocation reload failed")
	}
	request(http.StatusForbidden)
	request(http.StatusForbidden)
	if !p.Reload(cfg.Clone(), scanner.MustNew(cfg)) {
		t.Fatal("restoration reload failed")
	}
	request(http.StatusOK)
}
