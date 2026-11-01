// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBrowserURLLengthHTTPTransports(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.ForwardProxy.Enabled = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	for _, transport := range []string{"fetch", "forward"} {
		t.Run(transport, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				size int
				tail string
				want int
			}{
				{"browser URL", 2200, "", http.StatusOK},
				{"RFC limit", 8000, "", http.StatusOK},
				{"oversize", 8001, "", http.StatusForbidden},
				{"credential at end", 2400, "/ghp_" + strings.Repeat("A", 36), http.StatusForbidden},
			} {
				t.Run(tc.name, func(t *testing.T) {
					target := upstream.URL + "/" + strings.Repeat("a", tc.size-len(upstream.URL)-1-len(tc.tail)) + tc.tail
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
					w := httptest.NewRecorder()
					if transport == "fetch" {
						req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(target), nil)
						p.handleFetch(w, req)
					} else {
						p.handleForwardHTTP(w, req)
					}
					if w.Code != tc.want {
						t.Fatalf("status %d, want %d; %s", w.Code, tc.want, w.Body.String())
					}
				})
			}
		})
	}
}

func TestBrowserURLLengthInterceptAndIssuance(t *testing.T) {
	value := issuedTestToken()
	query := "/accounts/SetOSID?osidt=" + value
	path := "/_/scs/mail-static/_/js/k=gmail.main.en." + value + "/m=m_i"
	credential := "ghp_" + strings.Repeat("A", 36)
	credentialQuery := "/accounts/SetOSID?osidt=" + credential
	credentialPath := "/_/scs/mail-static/_/js/" + credential
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<a href="`+query+`">sign in</a><script src="`+path+`"></script><a href="`+credentialQuery+`">x</a><script src="`+credentialPath+`"></script>`)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	h := newWebPlatformHarness(t)
	for _, step := range []struct {
		name, path, agent string
		want              int
	}{
		{"query before issue", query, "one", http.StatusForbidden},
		{"path before issue", path, "one", http.StatusForbidden},
		{"deliver links", "/", "one", http.StatusOK},
		{"issued query", query, "one", http.StatusOK},
		{"issued path", path, "one", http.StatusOK},
		{"changed query", query + "x", "one", http.StatusForbidden},
		{"changed path", path + value, "one", http.StatusForbidden},
		{"other session", query, "two", http.StatusForbidden},
		{"issued query credential", credentialQuery, "one", http.StatusForbidden},
		{"issued path credential", credentialPath, "one", http.StatusForbidden},
		{"long browser URL", "/" + strings.Repeat("a", 2200), "one", http.StatusOK},
		{"long credential", "/" + strings.Repeat("a", 2200) + "/" + credential, "one", http.StatusForbidden},
		{"oversize", "/" + strings.Repeat("a", 8000), "one", http.StatusForbidden},
	} {
		t.Run(step.name, func(t *testing.T) {
			if got := h.do(upstream, step.path, step.agent, nil); got != step.want {
				t.Fatalf("status %d, want %d", got, step.want)
			}
		})
	}
}

func TestBrowserURLLengthReload(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	p := nestedURLReloadProxy(t, cfg)
	target := "https://api.vendor.example/" + strings.Repeat("a", 2200)
	for _, limit := range []int{8000, 2048, 2048, 8000, 8000} {
		next := config.Defaults()
		next.Internal = nil
		next.FetchProxy.Monitoring.MaxURLLength = limit
		if !p.Reload(next, scanner.MustNew(next)) {
			t.Fatal("reload failed")
		}
		got := p.scannerPtr.Load().Scan(t.Context(), target)
		if got.Allowed != (limit == 8000) {
			t.Fatalf("limit %d: %+v", limit, got)
		}
	}
}

func TestBrowserURLLengthWebSocket(t *testing.T) {
	backend, closeBackend := wsEchoServer(t)
	defer closeBackend()
	proxy, closeProxy := setupWSProxy(t, nil)
	defer closeProxy()
	for _, tc := range []struct {
		name string
		size int
		tail string
		want bool
	}{
		{"browser URL", 2200, "", true},
		{"oversize", 8001, "", false},
		{"credential at end", 2400, "/ghp_" + strings.Repeat("A", 36), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := "ws://" + backend + "/"
			target := base + strings.Repeat("a", tc.size-len(base)-len(tc.tail)) + tc.tail
			conn, err := dialWSConnToTarget(proxy, target)
			if conn != nil {
				_ = conn.Close()
			}
			if (err == nil) != tc.want {
				t.Fatalf("connected=%v, want %v; err=%v", err == nil, tc.want, err)
			}
		})
	}
}
