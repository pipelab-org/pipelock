// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

const nestedMetadataQuery = "target=http://169.254.169.254/latest/meta-data/"

func nestedURLProxyConfig() *config.Config {
	cfg := config.Defaults()
	cfg.APIAllowlist = nil
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.FetchProxy.Monitoring.EntropyThreshold = 8.0
	cfg.DLP.Patterns = nil
	return cfg
}

func TestFetchEndpoint_NestedMetadataURLBlocked(t *testing.T) {
	cfg := nestedURLProxyConfig()
	logger := audit.NewNop()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	target := "https://mirror.vendor.example/pkg?" + nestedMetadataQuery
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(target), nil)
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 body=%s", w.Code, w.Body.String())
	}
	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !resp.Blocked {
		t.Fatal("expected blocked=true")
	}
	if !strings.Contains(resp.BlockReason, "nested URL") {
		t.Fatalf("block_reason=%q want nested URL", resp.BlockReason)
	}
}

// nestedURLBackendPath is the only path the forward-proxy tests below send.
const nestedURLBackendPath = "/pkg"

// newNestedURLCountingBackend excludes queryless GET / loopback probes.
// Other requests count even if their path differs from the requested path, so
// a forwarding regression cannot hide an upstream contact by changing the path.
func newNestedURLCountingBackend(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	backend := newIPv4Server(t, ignoreLoopbackPortProbes(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprint(w, "ok")
	})))
	return backend, &hits
}

func TestNestedURLCountingBackendIgnoresForeignProbe(t *testing.T) {
	backend, hits := newNestedURLCountingBackend(t)
	defer backend.Close()
	get := func(target string) int {
		t.Helper()
		resp := doGet(t, backend.Client(), target)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if status := get(backend.URL + "/"); status != http.StatusNotFound || hits.Load() != 0 {
		t.Fatalf("foreign probe: status=%d hits=%d, want 404 and 0", status, hits.Load())
	}
	var wantHits int32
	for _, path := range []string{nestedURLBackendPath, "/other", "/", "/%70kg"} {
		wantHits++
		if status := get(backend.URL + path + "?" + nestedMetadataQuery); status != http.StatusOK || hits.Load() != wantHits {
			t.Fatalf("own request path=%q: status=%d hits=%d, want 200 and %d", path, status, hits.Load(), wantHits)
		}
	}
	if status := get(backend.URL + "/"); status != http.StatusNotFound || hits.Load() != 4 {
		t.Fatalf("later foreign probe: status=%d hits=%d, want 404 and 4", status, hits.Load())
	}
}

func TestForwardHTTP_NestedMetadataURLBlocked(t *testing.T) {
	backend, hits := newNestedURLCountingBackend(t)
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.FetchProxy.Monitoring.EntropyThreshold = 8.0
		cfg.DLP.Patterns = nil
	})
	defer cleanup()

	partial := "http://169%2e254.169.254/latest/meta-data/"
	for _, tc := range []struct {
		name      string
		query     string
		wantAllow bool
	}{
		{"plaintext", nestedMetadataQuery, false},
		{"base64_partial_percent", "target=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(partial))), false},
		{"benign", "target=" + url.QueryEscape("https://api.vendor.example/read"), true},
		{"benign_base64", "target=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("https://api.vendor.example/read"))), true},
		{"benign_base64_partial_percent", "target=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("https://api%2evendor.example/read"))), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := hits.Load()
			resp := doGet(t, proxyClient(proxyAddr), backend.URL+nestedURLBackendPath+"?"+tc.query)
			defer func() { _ = resp.Body.Close() }()
			wantStatus, wantHits := http.StatusForbidden, before
			if tc.wantAllow {
				wantStatus, wantHits = http.StatusOK, before+1
			}
			if resp.StatusCode != wantStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want %d body=%s", resp.StatusCode, wantStatus, body)
			}
			if got := hits.Load(); got != wantHits {
				t.Fatalf("upstream hits=%d want %d", got, wantHits)
			}
		})
	}
}

func TestInterceptTunnel_NestedMetadataURLBlocked(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.FetchProxy.Monitoring.EntropyThreshold = 8.0
	cfg.DLP.Patterns = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	addr := upstream.Listener.Addr().String()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+addr+"/api?"+nestedMetadataQuery, nil)
	resp := interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, m, req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want 403", resp.StatusCode)
	}
	// A 403 alone is satisfied by a proxy that forwards first and refuses after.
	// The destination must never be contacted.
	if hits.Load() != 0 {
		t.Fatalf("upstream contacted %d time(s) despite a nested metadata destination", hits.Load())
	}
}

func TestFetchEndpoint_RedirectNestedMetadataURLBlocked(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://mirror.vendor.example/pkg?"+nestedMetadataQuery, http.StatusFound)
	}))
	defer backend.Close()

	cfg := nestedURLProxyConfig()
	cfg.FetchProxy.TimeoutSeconds = 5
	logger := audit.NewNop()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(backend.URL+"/start"), nil)
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 body=%s", w.Code, w.Body.String())
	}
	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !resp.Blocked {
		t.Fatal("expected blocked=true")
	}
	if !strings.Contains(resp.BlockReason, "nested URL") {
		t.Fatalf("block_reason=%q want nested URL", resp.BlockReason)
	}
}

func TestSubmitProfile_NestedMetadataURLBlocked(t *testing.T) {
	upstream, upstreamHits := newNestedURLCountingBackend(t)
	defer upstream.Close()

	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
	cfg.FetchProxy.Monitoring.EntropyThreshold = 8.0
	cfg.DLP.Patterns = nil
	proxy := submitProfileReverseProxy(t, cfg, upstreamURL)

	reqURL := proxy.URL + "/v1/batch?" + nestedMetadataQuery
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, reqURL, strings.NewReader(`{"clean":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want 403", resp.StatusCode)
	}
	if upstreamHits.Load() != 0 {
		t.Fatal("upstream invoked despite nested metadata URL")
	}
}
