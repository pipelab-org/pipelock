// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestWatchOnlyHTTPPreservesRepresentations(t *testing.T) {
	for _, transport := range []string{TransportForward, "intercept"} {
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
				cfg.RequestBodyScanning.MaxBodyBytes = 4
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
	if urlResultBlocks(cfg, sc, target, floor) {
		t.Fatal("watch-only blocked inspection limit")
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if watchRequestDecision(req, watchHTTPOptions{Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New(), Transport: TransportForward}) {
		t.Fatal("watch-only classified inspection limit as credential")
	}
	cfg.WatchOnly = false
	if !urlResultBlocks(cfg, sc, target, floor) {
		t.Fatal("unset behavior changed")
	}
}

func TestWatchOnlyCONNECTIdleReload(t *testing.T) {
	client, relayClient := net.Pipe()
	upstream, relayUpstream := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	var watch atomic.Bool
	watch.Store(true)
	observed := make(chan struct{}, 1)
	relay := &tunnelRelay{
		client: relayClient, target: relayUpstream, idleTimeout: 10 * time.Millisecond, clockStart: time.Now(), watchOnly: watch.Load,
		observe: func(_ string, enforced bool) {
			if enforced {
				t.Error("idle enforced in watch-only")
			}
			select {
			case observed <- struct{}{}:
			default:
			}
		},
	}
	done := make(chan struct{})
	go func() { relay.run(); close(done) }()
	defer relay.closeBoth()
	select {
	case <-observed:
	case <-time.After(5 * time.Second):
		t.Fatal("idle limit not observed")
	}
	sent := make(chan error, 1)
	go func() { _, err := client.Write([]byte("unchanged")); sent <- err }()
	if err := upstream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len("unchanged"))
	if _, err := io.ReadFull(upstream, received); err != nil || string(received) != "unchanged" {
		t.Fatalf("relay changed after idle: %q %v", received, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	watch.Store(false)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle enforcement not restored on reload")
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
	if w.Code != http.StatusOK || w.Body.String() != "unchanged" {
		t.Fatalf("required receipt interrupted watch: %d %q", w.Code, w.Body.String())
	}
	stats := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(stats, req)
	var body struct {
		Bytes int64 `json:"watch_only_uninspected_bytes"`
	}
	if err := json.Unmarshal(stats.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Bytes != int64(len("unchanged")) {
		t.Fatalf("uninspected bytes=%d", body.Bytes)
	}
}

func TestWatchOnlyInterceptIssuerCookieLifecycle(t *testing.T) {
	_, _, cfg, _, _, m := testInterceptSetup(t)
	cfg.Internal, cfg.WatchOnly = nil, true
	cfg.TLSInterception.Enabled = true
	issuerCookieTestConfig(t, cfg)
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, m)
	if err != nil {
		sc.Close()
		t.Fatal(err)
	}
	defer p.Close()
	value := issuerAWSShapedValue()
	ic := &InterceptContext{Config: cfg, Proxy: p, Agent: "test-agent", ActorAuth: envelope.ActorAuthBound}
	upstream := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		headers := http.Header{"Content-Type": {"text/plain"}}
		if r.URL.Path == "/login" {
			headers.Add("Set-Cookie", "session="+value+"; Path=/; Secure")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: io.NopCloser(strings.NewReader("unchanged")), Request: r}, nil
	})
	for _, tc := range []struct {
		name, target string
		cookie       bool
		status       int
	}{
		{"unissued", "https://api.vendor.example/account", true, http.StatusForbidden},
		{"issuance", "https://api.vendor.example/login", false, http.StatusOK},
		{"issuer return", "https://api.vendor.example/account", true, http.StatusOK},
		{"other destination", "https://other.vendor.example/account", true, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.target, nil)
			if tc.cookie {
				req.Header.Set("Cookie", "session="+value)
			}
			w := httptest.NewRecorder()
			serveWatchHTTP(w, req, watchHTTPOptions{Intercept: ic, Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: m, Transport: "intercept", Upstream: upstream, Proxy: p, Agent: ic.Agent, ActorAuth: ic.ActorAuth, MaxResponseBytes: 1024})
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.status, w.Body)
			}
		})
	}
}

func TestWatchOnlyCONNECTEntryPoint(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		watch, credential, kill bool
		status                  int
	}{
		{"unset blocks policy", false, false, false, http.StatusForbidden},
		{"watch forwards", true, false, false, http.StatusOK},
		{"watch credential floor", true, true, false, http.StatusForbidden},
		{"watch kill switch", true, false, true, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := listenEcho(t)
			defer func() { _ = upstream.Close() }()
			cfg := config.Defaults()
			cfg.WatchOnly = tc.watch
			cfg.Internal = nil
			cfg.ForwardProxy.Enabled = true
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
			cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
			cfg.RequestBodyScanning.Enabled, cfg.RequestBodyScanning.ScanHeaders = true, true
			cfg.KillSwitch.Enabled = tc.kill
			disabled := false
			cfg.ForwardProxy.SNIVerification = &disabled
			sc := scanner.MustNew(cfg)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithKillSwitch(killswitch.New(cfg)))
			if err != nil {
				sc.Close()
				t.Fatal(err)
			}
			defer p.Close()
			server := httptest.NewServer(p.Handler())
			defer server.Close()
			address := server.Listener.Addr().String()
			conn := dialProxy(t, address)
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			header := ""
			if tc.credential {
				header = "X-Api-Key: " + auditFloorValue("core") + "\r\n"
			}
			_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", upstream.Addr(), upstream.Addr(), header)
			if err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != tc.status {
				t.Fatalf("status=%d want=%d", response.StatusCode, tc.status)
			}
			if tc.status != http.StatusOK {
				return
			}
			payload := "unchanged tunnel payload"
			if _, err := io.WriteString(conn, payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(reader, got); err != nil || string(got) != payload {
				t.Fatalf("tunnel changed: %q %v", got, err)
			}
		})
	}
}
