// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
		{"header with configured default", "directory-agent", envelope.ActorAuthSelfDeclared, http.StatusForbidden, http.StatusOK, nil},
		{"anonymous", "", envelope.ActorAuthUnknown, http.StatusForbidden, http.StatusForbidden, nil},
		{"self declared", "", envelope.ActorAuthSelfDeclared, http.StatusForbidden, http.StatusForbidden, nil},
		{"matched header", "", envelope.ActorAuthMatched, http.StatusForbidden, http.StatusForbidden, nil},
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
			for _, path := range []string{
				items + serverIDListed + ":/report.txt:/content",
				items + serverIDListed + "%3A/report.txt%3A/content",
				items + "%41" + serverIDListed[1:] + ":/nested/report.txt:/content",
			} {
				if got := do(path); got != tc.want {
					t.Fatalf("relative path %s = %d, want %d", path, got, tc.want)
				}
				if got := doAt(other, path); got != http.StatusForbidden {
					t.Fatalf("relative path at different origin = %d, want 403", got)
				}
			}
			for _, path := range []string{
				items + serverIDListed + ":/" + agentBlob + ":/content",
				items + serverIDListed + ":" + agentBlob + "/report.txt:/content",
				items + serverIDListed + "::/report.txt:/content",
				items + serverIDListed + "%253A/report.txt:/content",
				items + serverIDListed + ":/report.txt:/content?q=" + agentBlob,
				items + serverIDListed + ":/" + issuerUnissuedSecret() + ":/content",
			} {
				if got := do(path); got != http.StatusForbidden {
					t.Fatalf("additional content %s = %d, want 403", path, got)
				}
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

func TestInterceptServerIssuedIDRelativeUpload(t *testing.T) {
	h := newWebPlatformHarness(t)
	var uploads atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/listing" {
			_, _ = io.WriteString(w, `{"value":[{"id":"`+serverIDListed+`"},{"id":"`+agentBlob+`"}]}`)
			return
		}
		if r.Method == http.MethodPut {
			uploads.Add(1)
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	const agent = "directory-agent"
	path := "/v1.0/me/drive/items/" + serverIDListed + ":/report.txt:/content"
	if got := h.send(upstream, http.MethodPut, path, agent, "text/plain", "report"); got != http.StatusForbidden {
		t.Fatalf("unissued upload = %d, want 403", got)
	}
	// A header send is recorded even when the server later lists that value
	// as an ID. The colon delimiter must not turn a reflection into an issue.
	if got := h.sendHeader(upstream, http.MethodGet, "/submit", agent, "X-Criteria", agentBlob, ""); got != http.StatusNoContent {
		t.Fatalf("submit = %d", got)
	}
	if got := h.send(upstream, http.MethodGet, "/listing", agent, "", ""); got != http.StatusOK {
		t.Fatalf("listing = %d", got)
	}
	if got := h.send(upstream, http.MethodPut, path, agent, "text/plain", "report"); got != http.StatusCreated {
		t.Fatalf("issued upload = %d, want 201", got)
	}
	for _, tc := range []struct {
		name, path, agent string
	}{
		{"reflected", strings.Replace(path, serverIDListed, agentBlob, 1), agent},
		{"other session", path, "peer-agent"},
		{"payload filename", strings.Replace(path, "report.txt", agentBlob, 1), agent},
		{"encoded payload", strings.Replace(path, "report.txt", "%4B"+agentBlob[1:], 1), agent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.send(upstream, http.MethodPut, tc.path, tc.agent, "text/plain", "report"); got != http.StatusForbidden {
				t.Fatalf("upload = %d, want 403", got)
			}
		})
	}
	if got := uploads.Load(); got != 1 {
		t.Fatalf("upstream uploads = %d, want exactly one", got)
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
	// client address. Untrusted names confer no allowance; bound identities
	// keep independent evidence even though their address is identical.
	do := func(path, agent, criteria string, auth envelope.ActorAuth, want int) {
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
			Agent: agent, ActorAuth: auth,
		})
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s as %s = %d, want %d", path, agent, resp.StatusCode, want)
		}
	}
	do("/items/"+serverIDListed, "caller-b", "", envelope.ActorAuthSelfDeclared, http.StatusForbidden)
	do("/submit", "caller-a", agentBlob, envelope.ActorAuthSelfDeclared, http.StatusNoContent)
	do("/listing", "caller-a", "", envelope.ActorAuthSelfDeclared, http.StatusOK)
	do("/items/"+serverIDListed, "caller-b", "", envelope.ActorAuthSelfDeclared, http.StatusForbidden)
	do("/items/"+agentBlob, "caller-b", "", envelope.ActorAuthSelfDeclared, http.StatusForbidden)
	do("/listing", "caller-a", "", envelope.ActorAuthBound, http.StatusOK)
	do("/items/"+serverIDListed, "caller-a", "", envelope.ActorAuthBound, http.StatusOK)
	do("/items/"+serverIDListed, "caller-a", "", envelope.ActorAuthUnknown, http.StatusForbidden)
	do("/items/"+serverIDListed, "caller-a", "", envelope.ActorAuthMatched, http.StatusForbidden)
	do("/items/"+serverIDListed, "caller-b", "", envelope.ActorAuthBound, http.StatusForbidden)
	do("/listing", "caller-b", "", envelope.ActorAuthBound, http.StatusOK)
	do("/items/"+serverIDListed, "caller-b", "", envelope.ActorAuthBound, http.StatusOK)
}
