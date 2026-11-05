// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestInterceptTunnel_GitHubActionsResultsSAS(t *testing.T) {
	const host = "productionresultssa32.blob.core.windows.net"
	const run = "/actions-results/00000000-0000-4000-8000-000000000011/workflow-job-run-00000000-0000-4000-8000-000000000012"
	query, err := url.ParseQuery(releaseGrantSASQuery("unused", "actions-interception"))
	if err != nil {
		t.Fatal(err)
	}
	query.Del("jwt")
	query.Set("st", "2026-10-03T21:59:55Z")
	query.Set("se", "2026-10-03T22:10:00Z")
	query.Set("rscd", `attachment; filename="test-results-linux-amd64-release-archive.zip"`)
	query.Set("rsct", "application/zip")
	good := query.Encode()
	for _, tc := range []struct {
		name, host, path, query, carrier string
		wantAllow                        bool
	}{
		{"log", host, run + "/logs/job/job-logs.txt", good, "", true},
		{"artifact", host, run + "/artifacts/" + strings.Repeat("0123456789abcdef", 4) + ".zip", good, "", true},
		{"unpublished account", "productionresultssa99.blob.core.windows.net", run + "/logs/job/job-logs.txt", good, "", false},
		{"body carrier", host, run + "/logs/job/job-logs.txt", good, "body", false},
		{"header carrier", host, run + "/logs/job/job-logs.txt", good, "header", false},
		{"second credential", host, run + "/logs/job/job-logs.txt", good + "&x=ghp_" + strings.Repeat("a", 36), "", false},
		{"lifetime over cap", host, run + "/logs/job/job-logs.txt", strings.Replace(good, "2026-10-03T22%3A10%3A00Z", "2026-10-04T21%3A59%3A56Z", 1), "", false},
		{"lookalike", host + ".vendor.example", run + "/logs/job/job-logs.txt", good, "", false},
		{"bad path", host, "/other/job-logs.txt", good, "", false},
		{"duplicate signature", host, run + "/logs/job/job-logs.txt", good + "&sig=" + url.QueryEscape(query.Get("sig")), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamHits atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				_, _ = fmt.Fprint(w, "asset")
			}))
			defer upstream.Close()

			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			addr := upstream.Listener.Addr().String()
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatalf("SplitHostPort: %v", err)
			}
			now := time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC)
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.ScanHeaders = true
			cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
			cfg.RequestBodyScanning.Action = config.ActionBlock
			sc := releaseGrantScanner(t, cfg, now)

			target := "https://" + tc.host + ":" + port + tc.path + "?" + tc.query
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
			if tc.carrier == "body" {
				req, _ = http.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(target))
				req.Header.Set("Content-Type", "text/plain")
			}
			if tc.carrier == "header" {
				req.Header.Set("X-Download", target)
			}

			dialer := &net.Dialer{}
			upstreamRT := upstream.Client().Transport.(*http.Transport).Clone()
			upstreamRT.TLSClientConfig = upstreamRT.TLSClientConfig.Clone()
			upstreamRT.TLSClientConfig.ServerName = upstream.Listener.Addr().(*net.TCPAddr).IP.String()
			upstreamRT.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			}
			t.Cleanup(upstreamRT.CloseIdleConnections)

			resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
				Upstream:   upstream,
				TargetHost: tc.host,
				UpstreamRT: upstreamRT,
				Cache:      cache,
				Pool:       pool,
				Config:     cfg,
				Scanner:    sc,
				Logger:     logger,
				Metrics:    m,
				Request:    req,
				Proxy:      &Proxy{captureObs: capture.NopObserver{}, metrics: m},
			})
			defer func() { _ = resp.Body.Close() }()

			if !tc.wantAllow {
				if resp.StatusCode != http.StatusForbidden || upstreamHits.Load() != 0 {
					t.Fatalf("SAS reached the upstream: status=%d hits=%d", resp.StatusCode, upstreamHits.Load())
				}
				return
			}
			if resp.StatusCode != http.StatusOK || upstreamHits.Load() != 1 {
				t.Fatalf("Actions results SAS blocked: status=%d hits=%d", resp.StatusCode, upstreamHits.Load())
			}
			assertMetricSampleValue(t, m,
				`pipelock_dlp_credential_audience_allows_total{pattern="Azure SAS Token",surface="url"}`, 1)
		})
	}
}

// Inside a TLS-intercepted tunnel, an allowed results download is a
// structural exemption and earns no clean credit; a plain clean download from
// the same host does, which shows the recorder would see the credit.
func TestInterceptTunnel_GitHubActionsResultsSASEarnsNoCleanCredit(t *testing.T) {
	const host = "productionresultssa32.blob.core.windows.net"
	const path = "/actions-results/00000000-0000-4000-8000-000000000011/workflow-job-run-00000000-0000-4000-8000-000000000012/logs/job/job-logs.txt"
	query, err := url.ParseQuery(releaseGrantSASQuery("unused", "actions-intercept-decay"))
	if err != nil {
		t.Fatal(err)
	}
	query.Del("jwt")
	query.Set("st", "2026-10-03T21:59:55Z")
	query.Set("se", "2026-10-03T22:10:00Z")
	for _, tc := range []struct {
		name, query string
		wantCredit  bool
	}{
		{"sas grant", "?" + query.Encode(), false},
		{"plain clean control", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = fmt.Fprint(w, "download bytes")
			}))
			defer upstream.Close()
			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			cfg.AdaptiveEnforcement.Enabled = true
			cfg.AdaptiveEnforcement.EscalationThreshold = 100
			addr := upstream.Listener.Addr().String()
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatalf("SplitHostPort: %v", err)
			}
			sc := releaseGrantScanner(t, cfg, time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC))
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+":"+port+path+tc.query, nil)
			dialer := &net.Dialer{}
			upstreamRT := upstream.Client().Transport.(*http.Transport).Clone()
			upstreamRT.TLSClientConfig = upstreamRT.TLSClientConfig.Clone()
			upstreamRT.TLSClientConfig.ServerName = upstream.Listener.Addr().(*net.TCPAddr).IP.String()
			upstreamRT.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			}
			t.Cleanup(upstreamRT.CloseIdleConnections)
			rec := &interceptMockRecorder{}
			resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
				Upstream:   upstream,
				TargetHost: host,
				UpstreamRT: upstreamRT,
				Cache:      cache,
				Pool:       pool,
				Config:     cfg,
				Scanner:    sc,
				Logger:     logger,
				Metrics:    m,
				Request:    req,
				Recorder:   rec,
				Proxy:      &Proxy{captureObs: capture.NopObserver{}, metrics: m},
			})
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("download refused: status=%d", resp.StatusCode)
			}
			if rec.cleanCalled != tc.wantCredit {
				t.Fatalf("clean credit = %v, want %v", rec.cleanCalled, tc.wantCredit)
			}
		})
	}
}

// Fetch scans the redirect before dialing storage. HTTPS through the forward
// proxy is covered by TestInterceptTunnel_GitHubActionsResultsSAS; cleartext
// absolute-URI requests never earn this HTTPS-only grant.
func TestFetchEndpoint_GitHubActionsResultsSASRedirect(t *testing.T) {
	const host = "productionresultssa32.blob.core.windows.net"
	const blob = "/actions-results/00000000-0000-4000-8000-000000000011/workflow-job-run-00000000-0000-4000-8000-000000000012"
	query, err := url.ParseQuery(releaseGrantSASQuery("unused", "actions-fetch"))
	if err != nil {
		t.Fatal(err)
	}
	query.Del("jwt")
	query.Set("st", "2026-10-03T21:59:55Z")
	query.Set("se", "2026-10-03T22:10:00Z")
	for _, tc := range []struct {
		name, host, path, extra string
		allow                   bool
	}{
		{"log", host, blob + "/logs/job/job-logs.txt", "", true},
		{"artifact", host, blob + "/artifacts/" + strings.Repeat("0123456789abcdef", 4) + ".zip", "", true},
		{"unpublished account", "productionresultssa200.blob.core.windows.net", blob + "/logs/job/job-logs.txt", "", false},
		{"wrong path", host, "/other/job-logs.txt", "", false},
		{"second credential", host, blob + "/logs/job/job-logs.txt", "&x=ghp_" + strings.Repeat("a", 36), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var storageHits atomic.Int32
			storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				storageHits.Add(1)
				w.Header().Set("Content-Type", "text/plain")
				_, _ = fmt.Fprint(w, "download bytes")
			}))
			defer storage.Close()
			origin := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+tc.host+tc.path+"?"+query.Encode()+tc.extra, http.StatusFound)
			}))
			defer origin.Close()
			cfg := config.Defaults()
			cfg.FetchProxy.TimeoutSeconds = 5
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			cfg.APIAllowlist = nil
			sc := releaseGrantScanner(t, cfg, time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC))
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			pool := x509.NewCertPool()
			pool.AddCert(storage.Certificate())
			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					switch addr {
					case "github.example:80":
						addr = origin.Listener.Addr().String()
					case tc.host + ":443":
						addr = storage.Listener.Addr().String()
					default:
						return nil, fmt.Errorf("unexpected destination %s", addr)
					}
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
				TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
			}
			t.Cleanup(transport.CloseIdleConnections)
			p.client.Transport = transport
			w := serveFetch(t, p, "http://github.example/repos/OWNER/REPO/actions/jobs/123/logs")
			if tc.allow {
				if w.Code != http.StatusOK || storageHits.Load() != 1 || !strings.Contains(w.Body.String(), "download bytes") {
					t.Fatalf("download refused: status=%d hits=%d body=%s", w.Code, storageHits.Load(), w.Body.String())
				}
			} else if w.Code != http.StatusForbidden || storageHits.Load() != 0 {
				t.Fatalf("invalid grant reached storage: status=%d hits=%d", w.Code, storageHits.Load())
			}
		})
	}
}

// A results download is a structural exemption, which is adaptive-neutral: it
// must neither raise a session's score nor earn clean-traffic credit, so a run
// of log fetches can't wash out earlier findings. The control is a plain clean
// download from the same host, which does earn credit.
func TestFetchEndpoint_GitHubActionsResultsSASEarnsNoCleanCredit(t *testing.T) {
	const host = "productionresultssa32.blob.core.windows.net"
	const blob = "/actions-results/00000000-0000-4000-8000-000000000011/workflow-job-run-00000000-0000-4000-8000-000000000012/logs/job/job-logs.txt"
	const client = "127.0.0.1"
	query, err := url.ParseQuery(releaseGrantSASQuery("unused", "actions-decay"))
	if err != nil {
		t.Fatal(err)
	}
	query.Del("jwt")
	query.Set("st", "2026-10-03T21:59:55Z")
	query.Set("se", "2026-10-03T22:10:00Z")
	for _, tc := range []struct {
		name, location string
		wantCredit     bool
	}{
		{"sas grant", "https://" + host + blob + "?" + query.Encode(), false},
		{"plain clean control", "https://" + host + blob, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = fmt.Fprint(w, "download bytes")
			}))
			defer storage.Close()
			origin := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.location, http.StatusFound)
			}))
			defer origin.Close()
			cfg := config.Defaults()
			cfg.FetchProxy.TimeoutSeconds = 5
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			cfg.APIAllowlist = nil
			cfg.SessionProfiling.Enabled = true
			cfg.AdaptiveEnforcement.Enabled = true
			cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0.5
			cfg.ApplyDefaults()
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			sc := releaseGrantScanner(t, cfg, time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC))
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			pool := x509.NewCertPool()
			pool.AddCert(storage.Certificate())
			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					switch addr {
					case "github.example:80":
						addr = origin.Listener.Addr().String()
					case host + ":443":
						addr = storage.Listener.Addr().String()
					default:
						return nil, fmt.Errorf("unexpected destination %s", addr)
					}
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
				TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
			}
			t.Cleanup(transport.CloseIdleConnections)
			p.client.Transport = transport
			rec := p.sessionMgrPtr.Load().GetOrCreate(client)
			scope := adaptiveScopeForHost(host)
			rec.RecordScopedSignal(scope, session.SignalBlock, cfg.AdaptiveEnforcement.EscalationThreshold)
			before := rec.ScopedThreatScore(scope)
			if before <= 0 {
				t.Fatalf("seeded score = %v, want > 0", before)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
				"/fetch?url="+url.QueryEscape("http://github.example/repos/OWNER/REPO/actions/jobs/123/logs"), nil)
			req.RemoteAddr = client + ":12345"
			w := httptest.NewRecorder()
			p.handleFetch(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("download refused: status=%d body=%s", w.Code, w.Body.String())
			}
			after := rec.ScopedThreatScore(scope)
			if tc.wantCredit && after >= before {
				t.Fatalf("clean control earned no credit: before=%v after=%v", before, after)
			}
			if !tc.wantCredit && after != before {
				t.Fatalf("structural exemption changed the score: before=%v after=%v", before, after)
			}
		})
	}
}

func TestForwardProxy_GitHubActionsResultsSASCleartext(t *testing.T) {
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, nil)
	var upstreamDials atomic.Int32
	p.client.Transport = &http.Transport{DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
		upstreamDials.Add(1)
		return nil, fmt.Errorf("unexpected upstream dial to %s", addr)
	}}
	defer cleanup()
	transport := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: proxyAddr}, nil }}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	query, err := url.ParseQuery(releaseGrantSASQuery("unused", "actions-cleartext"))
	if err != nil {
		t.Fatal(err)
	}
	query.Del("jwt")
	// This proxy uses the real clock. Use GitHub's issued 605-second window
	// and prove the HTTPS control before testing cleartext.
	now := time.Now().UTC()
	start := now.Add(-5 * time.Second)
	query.Set("st", start.Format(time.RFC3339))
	query.Set("se", start.Add(605*time.Second).Format(time.RFC3339))
	target := "https://productionresultssa32.blob.core.windows.net/actions-results/00000000-0000-4000-8000-000000000011/workflow-job-run-00000000-0000-4000-8000-000000000012/logs/job/job-logs.txt?" + query.Encode()
	cfg := config.Defaults()
	cfg.Internal = nil
	control := releaseGrantScanner(t, cfg, now).Scan(context.Background(), target)
	if !control.Allowed {
		t.Fatalf("HTTPS control blocked: %s", control.Reason)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		strings.Replace(target, "https://", "http://", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden || upstreamDials.Load() != 0 {
		t.Fatalf("status=%d dials=%d, want 403 before dialing", resp.StatusCode, upstreamDials.Load())
	}
}
