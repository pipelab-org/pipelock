// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestWatchDisabledBodyScanningParity(t *testing.T) {
	for _, tc := range []struct{ name, body, encoding, contentType string }{
		{"gzip", "ordinary", "gzip", "text/plain"},
		{"brotli", "ordinary", "br", "text/plain"},
		{"oversize", strings.Repeat("ordinary", 256), "", "text/plain"},
		{"deep JSON", strings.Repeat("[", 65) + "1" + strings.Repeat("]", 65), "", "application/json"},
	} {
		for _, watch := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/watch=%t", tc.name, watch), func(t *testing.T) {
				upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					got, err := io.ReadAll(r.Body)
					if err != nil || string(got) != tc.body {
						t.Errorf("body changed: %q %v", got, err)
					}
					w.WriteHeader(http.StatusOK)
				}))
				defer upstream.Close()
				_, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
					auditFloorConfig(false, "")(cfg)
					cfg.WatchOnly = watch
					cfg.RequestBodyScanning.Enabled = false
					cfg.RequestBodyScanning.MaxBodyBytes = 1024
				})
				defer cleanup()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL, strings.NewReader(tc.body))
				req.Header.Set("Content-Encoding", tc.encoding)
				req.Header.Set("Content-Type", tc.contentType)
				out := httptest.NewRecorder()
				p.handleForwardHTTP(out, req)
				if out.Code != http.StatusOK {
					t.Fatalf("disabled body scanning: status=%d body=%s", out.Code, out.Body)
				}
			})
		}
	}
}

func TestWatchUpstreamRefusalEvidence(t *testing.T) {
	for _, surface := range []string{TransportForward, TransportFetch} {
		for _, tc := range []struct {
			name   string
			err    error
			reason string
		}{
			{"metadata", &ssrfDialBlockError{reason: blockreason.SSRFMetadata, detail: "metadata destination refused"}, string(blockreason.SSRFMetadata)},
			{"redirect", newRedirectBlockedRequest("redirect", "destination refused"), string(blockreason.RedirectScanDenied)},
		} {
			t.Run(surface+"/"+tc.name, func(t *testing.T) {
				_, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) { cfg.WatchOnly = true })
				defer cleanup()
				helper := newReceiptProxyHelperWithMetrics(t, p.metrics)
				p.receiptEmitterPtr.Store(helper.emitter)
				rt := roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("wrapped: %w", tc.err) })
				cfg := p.cfgPtr.Load()
				out := httptest.NewRecorder()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, watchReloadTarget, nil)
				if surface == TransportFetch {
					p.client.Transport = rt
					req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(watchReloadTarget), nil)
					p.handleFetch(out, req)
					var body FetchResponse
					if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil {
						t.Fatal(err)
					}
					if !body.Blocked || body.BlockReason == "" {
						t.Errorf("fetch failed to report refusal: %+v", body)
					}
				} else {
					switch surface {
					case TransportForward:
						p.client.Transport = rt
						p.handleForwardHTTP(out, req)
					case "intercept":
						handler := newInterceptHandler(&InterceptContext{TargetHost: req.URL.Hostname(), TargetPort: "443", Config: cfg, Scanner: p.scannerPtr.Load(), Logger: p.logger, Metrics: p.metrics, Proxy: p}, rt)
						handler.ServeHTTP(out, req)
					case TransportReverse:
						rp := NewReverseProxy(req.URL, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
						rp.SetOwnerProxy(p)
						rp.proxy.Transport = rt
						rp.ServeHTTP(out, req)
					}
				}
				if out.Code != http.StatusForbidden || out.Header().Get("X-Pipelock-Block-Reason") != tc.reason {
					t.Errorf("refusal lost: status=%d headers=%v body=%s", out.Code, out.Header(), out.Body)
				}
				found := false
				for _, r := range helper.findReceipts(t) {
					if r.ActionRecord.Verdict == config.ActionBlock && strings.Contains(r.ActionRecord.Pattern, "enforced in watch-only") {
						found = true
					}
				}
				if !found {
					t.Error("missing marked block receipt")
				}
			})
		}
	}
}

func TestWatchDisabledBodyScanningRetainsA2A(t *testing.T) {
	for _, watch := range []bool{false, true} {
		_, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
			auditFloorConfig(false, "")(cfg)
			cfg.WatchOnly = watch
			cfg.RequestBodyScanning.Enabled = false
			cfg.A2AScanning.Enabled = true
		})
		defer cleanup()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, watchReloadTarget+"/message:send", strings.NewReader(`{"text":"`+auditFloorValue("core")+`"}`))
		req.Header.Set("Content-Type", "application/a2a+json")
		out := httptest.NewRecorder()
		p.handleForwardHTTP(out, req)
		if out.Code != http.StatusForbidden {
			t.Fatalf("watch=%t A2A floor lost: %d", watch, out.Code)
		}
	}
}

func TestWatchRequiredReceiptRefusalObservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.WatchOnly, cfg.FlightRecorder.RequireReceipts = true, true
	opts := watchHTTPOptions{Config: cfg, Logger: logger, Metrics: metrics.New(), Transport: TransportFetch}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, watchReloadTarget, nil)
	if opts.receipt(req, config.ActionAllow, "watch_only", "admission") {
		t.Fatal("required receipt unavailable but admitted")
	}
	logger.Close()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "watch_only_enforced") || !strings.Contains(string(data), `"enforced":true`) {
		t.Fatalf("receipt refusal logged as observation: %s", data)
	}
}

func TestWatchFetchRedirectFloorEvidence(t *testing.T) {
	var deniedHits atomic.Int32
	denied := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		deniedHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer denied.Close()
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, denied.URL+"/denied?token="+auditFloorValue("core"), http.StatusFound)
			return
		}
		deniedHits.Add(1)
	}))
	defer upstream.Close()
	_, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) { cfg.WatchOnly = true })
	defer cleanup()
	helper := newReceiptProxyHelperWithMetrics(t, p.metrics)
	p.receiptEmitterPtr.Store(helper.emitter)
	out := httptest.NewRecorder()
	p.handleFetch(out, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL+"/start"), nil))
	var body FetchResponse
	if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if out.Code != http.StatusForbidden || !body.Blocked || out.Header().Get("X-Pipelock-Block-Reason") != "redirect_scan_denied" || deniedHits.Load() != 0 {
		t.Fatalf("redirect refusal lost: status=%d body=%+v hits=%d", out.Code, body, deniedHits.Load())
	}
	for _, r := range helper.findReceipts(t) {
		if r.ActionRecord.Verdict == config.ActionBlock && strings.Contains(r.ActionRecord.Pattern, "enforced in watch-only") && r.ActionRecord.Target == denied.URL {
			return
		}
	}
	t.Fatal("no marked block receipt for refused redirect target")
}
