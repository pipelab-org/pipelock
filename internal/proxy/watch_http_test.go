// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"

	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestWatchOnlyHTTPPreservesRepresentations(t *testing.T) {
	for _, transport := range []string{TransportForward} {
		for _, tc := range []struct {
			name, body, encoding string
			status, maxBytes     int
		}{
			{"ordinary", "ordinary reply", "", http.StatusOK, 1024},
			{"ceiling", strings.Repeat("abc", 1000), "", http.StatusOK, 32},
			{"partial", "partial bytes", "", http.StatusPartialContent, 1024},
			{"encoded", "opaque encoding", "gzip", http.StatusOK, 1024},
			{"invalid_utf8", string([]byte{0xff, 0xfe, 'A'}), "", http.StatusOK, 1024},
		} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" {
						t.Error("untrusted proxy identity assertions forwarded")
					}
					if r.Header.Get("X-Vendor-Trace") != "retained" {
						t.Error("application header changed")
					}
					if r.Header.Get("Range") != "bytes=0-1" || r.Header.Get("If-None-Match") != "test-tag" {
						t.Error("request range/cache headers changed")
					}
					body, err := io.ReadAll(r.Body)
					if err != nil || string(body) != "watchprobe-12345678" {
						t.Errorf("request body changed: %q %v", body, err)
					}
					w.Header().Set("Content-Type", "text/plain")
					w.Header().Set("ETag", "test-tag")
					if tc.encoding != "" {
						w.Header().Set("Content-Encoding", tc.encoding)
					}
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.body)
				}))
				defer backend.Close()
				cfg := config.Defaults()
				cfg.WatchOnly = true
				cfg.Internal = nil
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.MaxBodyBytes = 1024
				cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Watch Probe", Regex: `watchprobe-[0-9]{8}`, Severity: config.SeverityHigh})
				sc := scanner.MustNew(cfg)
				defer sc.Close()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, backend.URL, strings.NewReader("watchprobe-12345678"))
				req.Header.Set("X-Vendor-Trace", "retained")
				req.Header.Set("X-Forwarded-For", "192.0.2.1")
				req.Header.Set("Forwarded", "for=192.0.2.1")
				req.Header.Set("Range", "bytes=0-1")
				req.Header.Set("If-None-Match", "test-tag")
				w := httptest.NewRecorder()
				upstream := http.DefaultTransport.(*http.Transport).Clone()
				upstream.DisableCompression = true
				defer upstream.CloseIdleConnections()
				serveWatchHTTP(w, req, watchHTTPOptions{Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New(), Transport: transport, Upstream: upstream, MaxResponseBytes: int64(tc.maxBytes)})
				if w.Code != tc.status || w.Body.String() != tc.body || w.Header().Get("ETag") != "test-tag" {
					t.Fatalf("status=%d body=%q headers=%v", w.Code, w.Body.String(), w.Header())
				}
			})
		}
	}
}

func TestWatchOnlyCredentialFloorAndKillSwitch(t *testing.T) {
	for _, surface := range []string{"url", "body", "header", "kill"} {
		t.Run(surface, func(t *testing.T) {
			var calls atomic.Int32
			backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
			defer backend.Close()
			cfg := config.Defaults()
			cfg.WatchOnly = true
			cfg.Internal = nil
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.ScanHeaders = true
			cfg.RequestBodyScanning.Action = config.ActionWarn
			cfg.KillSwitch.Enabled = surface == "kill"
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			req := auditFloorRequest(t, backend.URL, surface, auditFloorValue("core"))
			w := httptest.NewRecorder()
			serveWatchHTTP(w, req, watchHTTPOptions{Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New(), Transport: TransportForward, Upstream: http.DefaultTransport, KillSwitch: killswitch.New(cfg), MaxResponseBytes: 1024})
			if calls.Load() != 0 || (w.Code != http.StatusForbidden && w.Code != http.StatusServiceUnavailable) {
				t.Fatalf("floor failed: status=%d upstream calls=%d body=%s", w.Code, calls.Load(), w.Body)
			}
		})
	}
}

func TestWatchOnlyForwardAndFetchEntryPoints(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportFetch} {
		t.Run(transport, func(t *testing.T) {
			backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "unchanged")
			}))
			defer backend.Close()
			_, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				cfg.WatchOnly = true
				cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
			})
			defer cleanup()
			w := httptest.NewRecorder()
			if transport == TransportForward {
				p.handleForwardHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, backend.URL, nil))
			} else {
				p.handleFetch(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.example/fetch?url="+url.QueryEscape(backend.URL), nil))
			}
			if w.Code != http.StatusOK {
				t.Fatalf("%d: %s", w.Code, w.Body)
			}
			if transport == TransportForward && w.Body.String() != "unchanged" {
				t.Fatal(w.Body.String())
			}
			if transport == TransportFetch {
				var body FetchResponse
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Content != "unchanged" || body.Blocked {
					t.Fatalf("%+v %v", body, err)
				}
			}
		})
	}
}

func TestWatchOnlyJSONStringStreaming(t *testing.T) {
	text := strings.Repeat("??\n\"\\", tunnelBufSize)
	var out bytes.Buffer
	if err := writeWatchJSONString(&out, strings.NewReader(text)); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := json.Unmarshal([]byte(`"`+out.String()+`"`), &got); err != nil || got != text {
		t.Fatalf("round trip mismatch: %v", err)
	}
}

func TestWatchOnlyURLInspectionLimit(t *testing.T) {
	cfg := config.Defaults()
	cfg.WatchOnly = true
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	nested := "%41"
	for range normalize.ScannerQueryUnescapeMaxRounds + 1 {
		nested = url.QueryEscape(nested)
	}
	target := "https://api.vendor.example/?q=" + nested
	floor := sc.ScanURLCoreFloor(target)
	if !scanner.IsURLInspectionLimitResult(floor) {
		t.Fatalf("fixture does not reach inspection limit: %+v", floor)
	}
	if !urlResultBlocks(cfg, sc, target, floor) {
		t.Fatal("watch-only released incomplete URL inspection")
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if !watchRequestDecision(req, watchHTTPOptions{Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New(), Transport: TransportForward}) {
		t.Fatal("watch-only released incomplete URL inspection")
	}
	cfg.WatchOnly = false
	if !urlResultBlocks(cfg, sc, target, floor) {
		t.Fatal("unset behavior changed")
	}
}

func TestWatchOnlyRequiredReceiptUnavailable(t *testing.T) {
	cfg := config.Defaults()
	cfg.WatchOnly = true
	cfg.FlightRecorder.RequireReceipts = true
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	m := metrics.New()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/resource", nil)
	w := httptest.NewRecorder()
	serveWatchHTTP(w, req, watchHTTPOptions{
		Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: m, Transport: TransportForward, MaxResponseBytes: 1024,
		Upstream: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("unchanged")), Request: r}, nil
		}),
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("required receipt did not refuse watch: %d %q", w.Code, w.Body.String())
	}
	stats := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(stats, req)
	var body struct {
		Bytes int64 `json:"watch_only_uninspected_bytes"`
	}
	if err := json.Unmarshal(stats.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Bytes != 0 {
		t.Fatalf("uninspected bytes=%d", body.Bytes)
	}
}
