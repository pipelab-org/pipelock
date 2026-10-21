// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A directory listing returns IDs inside a value array. The next request
// opens a new CONNECT tunnel and names one ID as an intermediate segment.
func TestInterceptServerIssuedDirectoryID(t *testing.T) {
	const listing = "/v1.0/me/drive/root/children"
	const items = "/v1.0/me/drive/items/"
	for _, tc := range []struct {
		name        string
		defaultName string
		auth        envelope.ActorAuth
		want        int
		wantLinked  int
		disable     func(*config.Config)
	}{
		{"operator bound", "", envelope.ActorAuthBound, http.StatusOK, http.StatusOK, nil},
		{"configured default", "directory-agent", envelope.ActorAuthConfigDefault, http.StatusOK, http.StatusOK, nil},
		{"header with configured default", "directory-agent", envelope.ActorAuthSelfDeclared, http.StatusOK, http.StatusOK, nil},
		{"anonymous", "", envelope.ActorAuthUnknown, http.StatusOK, http.StatusForbidden, nil},
		{"self declared", "", envelope.ActorAuthSelfDeclared, http.StatusOK, http.StatusForbidden, nil},
		{"matched header", "", envelope.ActorAuthMatched, http.StatusOK, http.StatusForbidden, nil},
		{"feature disabled", "", envelope.ActorAuthUnknown, http.StatusForbidden, http.StatusForbidden, func(c *config.Config) { c.RequestBodyScanning.IssuerBoundSessionCookies = false }},
		{"TLS interception disabled", "", envelope.ActorAuthUnknown, http.StatusForbidden, http.StatusForbidden, func(c *config.Config) { c.TLSInterception.Enabled = false }},
		{"body scanning disabled", "", envelope.ActorAuthUnknown, http.StatusForbidden, http.StatusForbidden, func(c *config.Config) { c.RequestBodyScanning.Enabled = false }},
		{"header scanning disabled", "", envelope.ActorAuthUnknown, http.StatusForbidden, http.StatusForbidden, func(c *config.Config) { c.RequestBodyScanning.ScanHeaders = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, pool, cfg, _, _, m := testInterceptSetup(t)
			issuerCookieTestConfig(t, cfg)
			cfg.DefaultAgentIdentity = tc.defaultName
			if tc.disable != nil {
				tc.disable(cfg)
			}
			logger := audit.NewNop()
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, logger, sc, m)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == listing {
					_, _ = io.WriteString(w, `{"value":[{"id":"`+serverIDListed+`","folder":{"childCount":1}}],"link":"/linked/`+serverIDOther+`","nextLink":"/listing?cursor=`+agentBlob+`"}`)
					return
				}
				_, _ = io.WriteString(w, `{"value":[]}`)
			}))
			t.Cleanup(upstream.Close)
			other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(other.Close)
			doAt := func(origin *httptest.Server, path string) int {
				t.Helper()
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
					Upstream: origin, Cache: cache, Pool: pool, Config: cfg, Scanner: sc,
					Logger: logger, Metrics: m, Request: req, Proxy: p,
					Agent: "directory-agent", ActorAuth: tc.auth,
				})
				defer func() { _ = resp.Body.Close() }()
				_, _ = io.Copy(io.Discard, resp.Body)
				return resp.StatusCode
			}
			do := func(path string) int { return doAt(upstream, path) }
			child := items + serverIDListed + "/children?$select=id,name,folder&$top=200"
			if got := do(child); got != http.StatusForbidden {
				t.Fatalf("before listing = %d, want 403", got)
			}
			if got := do(listing); got != http.StatusOK {
				t.Fatalf("listing = %d, want 200", got)
			}
			if got := do(child); got != tc.want {
				t.Fatalf("after listing = %d, want %d", got, tc.want)
			}
			if got := do(items + serverIDOther + "/children"); got != http.StatusForbidden {
				t.Fatalf("unissued sibling = %d, want 403", got)
			}
			if got := do(items + serverIDListed + "/" + agentBlob); got != http.StatusForbidden {
				t.Fatalf("additional unissued segment = %d, want 403", got)
			}
			if got := doAt(other, child); got != http.StatusForbidden {
				t.Fatalf("different origin = %d, want 403", got)
			}
			if got := do(child + "&q=" + agentBlob); got != http.StatusForbidden {
				t.Fatalf("unissued query = %d, want 403", got)
			}
			if got := do(items + serverIDListed + "/" + issuerUnissuedSecret()); got != http.StatusForbidden {
				t.Fatalf("credential beside issued ID = %d, want 403", got)
			}
			if got := do("/linked/" + serverIDOther); got != tc.wantLinked {
				t.Fatalf("linked path = %d, want %d", got, tc.wantLinked)
			}
			if got := do("/listing?cursor=" + agentBlob); got != tc.wantLinked {
				t.Fatalf("issued query = %d, want %d", got, tc.wantLinked)
			}
		})
	}
}

func TestInterceptServerIssuedIDSharedClientAddress(t *testing.T) {
	h := newWebPlatformHarness(t)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/submit" {
			if got := r.Header.Get("X-Criteria"); got != agentBlob {
				t.Errorf("submitted value = %q, want %q", got, agentBlob)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/listing" {
			_, _ = io.WriteString(w, `{"value":[{"id":"`+serverIDListed+`"},{"id":"`+agentBlob+`"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"value":[]}`)
	}))
	t.Cleanup(upstream.Close)
	// Each call opens a new tunnel; the helper gives both callers the same
	// client address. Their self-declared names do not isolate issuer state.
	do := func(path, agent, criteria string, want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if criteria != "" {
			req.Header.Set("X-Criteria", criteria)
		}
		resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
			Upstream: upstream, Cache: h.cache, Pool: h.pool, Config: h.cfg, Scanner: h.sc,
			Logger: h.logger, Metrics: h.m, Request: req, Proxy: h.p,
			Agent: agent, ActorAuth: envelope.ActorAuthSelfDeclared,
		})
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s as %s = %d, want %d", path, agent, resp.StatusCode, want)
		}
	}
	do("/items/"+serverIDListed, "caller-b", "", http.StatusForbidden)
	do("/submit", "caller-a", agentBlob, http.StatusNoContent)
	do("/listing", "caller-a", "", http.StatusOK)
	do("/items/"+serverIDListed, "caller-b", "", http.StatusOK)
	do("/items/"+agentBlob, "caller-b", "", http.StatusForbidden)
}
