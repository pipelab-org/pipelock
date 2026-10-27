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
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// An authorization server echoes state to the request's redirect_uri, even on
// an error redirect that needs no user (RFC 6749 section 4.1.2.1). A client
// registered by anyone, for example through dynamic registration (RFC 7591),
// can name a collector it owns. An endpoint grant must not turn that echo into
// a declared, server-issued callback value that then reaches the collector.
func TestNativeOAuthGrantCannotRelayStateToRemoteCallback(t *testing.T) {
	const collectorHost = "collector.vendor.example"
	secret := strings.Join([]string{"Qz7pW2mK", "x9R4tB6n", "Y1cV8hJ3", "fL5gD0sA"}, "")
	callback := "https://" + collectorHost + "/cb"
	var collected atomic.Int32
	collector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") == secret {
			collected.Add(1)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer collector.Close()
	const loopback = "http://127.0.0.1:49152/cb"
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both callbacks are registered for this client; echo state to the one named.
		q := r.URL.Query()
		target := loopback
		if q.Get("redirect_uri") == callback {
			target = callback
		}
		w.Header().Set("Location", target+"?error=invalid_scope&state="+url.QueryEscape(q.Get("state")))
		w.WriteHeader(http.StatusFound)
	}))
	defer idp.Close()

	cache, pool, cfg, _, _, m := testInterceptSetup(t)
	issuerCookieTestConfig(t, cfg)
	cfg.TLSInterception.Enabled = true
	cfg.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = []config.OAuthAuthorizationEndpoint{{Host: nativeOAuthProxyHost, Path: "/oauth/authorize"}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	do := func(server *httptest.Server, host, target string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
			Upstream: server, TargetHost: host, TargetPort: "443",
			UpstreamRT: interceptRewriteRoundTripper{base: server.Client().Transport, addr: server.Listener.Addr().String()},
			Cache:      cache, Pool: pool, Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: m,
			Request: req, Proxy: p, Agent: "agent-one", ActorAuth: envelope.ActorAuthBound,
		})
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	q := url.Values{"response_type": {"code"}, "client_id": {"registered-elsewhere"}, "redirect_uri": {loopback}, "state": {secret}, "scope": {"unknown"}}
	authorize := "https://" + nativeOAuthProxyHost + "/oauth/authorize?" + q.Encode()
	// Positive control: the grant is active here for a callback on this machine.
	if got := do(idp, nativeOAuthProxyHost, authorize); got != http.StatusFound {
		t.Fatalf("loopback authorization request: status=%d, want %d", got, http.StatusFound)
	}
	q.Set("redirect_uri", callback)
	authorize = "https://" + nativeOAuthProxyHost + "/oauth/authorize?" + q.Encode()
	if got := do(idp, nativeOAuthProxyHost, authorize); got != http.StatusForbidden {
		t.Errorf("authorization request naming a remote callback: status=%d, want %d", got, http.StatusForbidden)
	}
	if got := do(collector, collectorHost, callback+"?error=invalid_scope&state="+secret); got != http.StatusForbidden {
		t.Errorf("collector request carrying echoed state: status=%d, want %d", got, http.StatusForbidden)
	}
	if n := collected.Load(); n != 0 {
		t.Fatalf("collector received the state %d time(s)", n)
	}
}
