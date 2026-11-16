// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// TestInterceptTunnel_DNSInfrastructureError_NoSignal verifies that a DNS
// infrastructure error inside the intercept URL scan does NOT record a
// SignalBlock. recordSessionActivity alone does not cover this independent
// intercept signal path. A burst of intercepted HTTPS requests to a
// DNS-failing host must not escalate the session into airlock lockdown.
//
// The test uses the RFC 2606 reserved `.invalid` TLD in the intercept target
// and the HTTP request URL. Scanner DNS lookup on `.invalid` is guaranteed to
// fail regardless of the host machine's resolver config, so the block branch
// in intercept.go receives urlResult{Class: ClassInfrastructureError}.
func TestInterceptTunnel_DNSInfrastructureError_NoSignal(t *testing.T) {
	// Upstream used only to satisfy the TLS handshake target for the cert
	// cache; the intercept handler returns 403 from the URL scan before any
	// upstream connection is attempted, so the upstream body is never served.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream handler must not be reached when URL scan blocks")
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()

	cache, pool, _, _, logger, m := testInterceptSetup(t)

	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	cfg.TLSInterception.MaxResponseBytes = 1024 * 1024
	cfg.Internal = []string{"127.0.0.0/8"} // enable SSRF DNS resolution path
	enforceTrue := true
	cfg.Enforce = &enforceTrue
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = 5.0

	sc, err := scanner.NewWithOptions(cfg, scanner.Options{UpstreamResolver: failingInterceptResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sc.Close() })

	rec := &interceptMockRecorder{}

	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })

	// TargetHost is the DNS-unresolvable hostname. TLS MITM cert cache will
	// generate a cert for this ServerName; the test client validates it
	// against the test CA. No outbound DNS lookup is required for MITM cert
	// minting (pipelock signs for whatever ServerName is presented), so the
	// TLS handshake completes against the in-memory pipe.
	const invalidHost = "nonexistent.invalid"

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		_ = interceptTunnel(ctx, proxyConn, &InterceptContext{
			TargetHost: invalidHost,
			TargetPort: "443",
			Config:     cfg,
			Scanner:    sc,
			CertCache:  cache,
			Logger:     logger,
			Metrics:    m,
			ClientIP:   "10.0.0.1",
			RequestID:  "test-req-infra",
			UpstreamRT: upstream.Client().Transport,
			Recorder:   rec,
		})
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{
		RootCAs:    pool,
		ServerName: invalidHost,
	})
	t.Cleanup(func() { _ = tlsConn.Close() })

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		fmt.Sprintf("https://%s/path", invalidHost), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// Fail-closed preserved: DNS failure blocks the request.
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (fail-closed on DNS infrastructure error)", resp.StatusCode)
	}

	// The load-bearing assertion: no SignalBlock was recorded. Previously
	// (before the fix) this path would have recorded session.SignalBlock
	// (+3.0 points). Two such blocks in quick succession would escalate past
	// the threshold (5.0) and enter airlock hard tier.
	for _, sig := range rec.signals {
		if sig == session.SignalBlock {
			t.Errorf("DNS infrastructure error must NOT record SignalBlock in intercept URL path; got signals=%v", rec.signals)
		}
		if sig == session.SignalNearMiss {
			t.Errorf("DNS infrastructure error must NOT record SignalNearMiss either (neutral, not bounded); got signals=%v", rec.signals)
		}
	}
}

// TestInterceptTunnel_RealSSRF_RecordsSignalBlock is the paired regression
// guard. Must run alongside the infrastructure test - if this one silently
// stops recording SignalBlock too, the fix has broken adaptive escalation
// for genuine SSRF attempts.
func TestInterceptTunnel_RealSSRF_RecordsSignalBlock(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	cache, pool, _, _, logger, m := testInterceptSetup(t)

	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	cfg.TLSInterception.MaxResponseBytes = 1024 * 1024
	// Declare the upstream loopback IP as internal so SSRF blocks it.
	cfg.Internal = []string{testLoopbackIP + "/32"}
	enforceTrue := true
	cfg.Enforce = &enforceTrue
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = 100 // high so we don't actually escalate

	sc := scanner.MustNew(cfg)
	t.Cleanup(func() { sc.Close() })

	rec := &interceptMockRecorder{}

	host := upstream.Listener.Addr().(*net.TCPAddr).IP.String()
	addr := upstream.Listener.Addr().String()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+addr+"/path", nil)

	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		_ = interceptTunnel(ctx, proxyConn, &InterceptContext{
			TargetHost: host,
			TargetPort: fmt.Sprintf("%d", upstream.Listener.Addr().(*net.TCPAddr).Port),
			Config:     cfg,
			Scanner:    sc,
			CertCache:  cache,
			Logger:     logger,
			Metrics:    m,
			ClientIP:   "10.0.0.1",
			RequestID:  "test-req-real-ssrf",
			UpstreamRT: upstream.Client().Transport,
			Recorder:   rec,
		})
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{
		RootCAs:    pool,
		ServerName: host,
	})
	t.Cleanup(func() { _ = tlsConn.Close() })

	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (real SSRF must block)", resp.StatusCode)
	}

	// Real SSRF must STILL record SignalBlock. This is the invariant we
	// must not weaken - the fix excludes ONLY infrastructure errors from
	// scoring, not actual private-IP resolutions.
	foundBlock := false
	for _, sig := range rec.signals {
		if sig == session.SignalBlock {
			foundBlock = true
		}
	}
	if !foundBlock {
		t.Errorf("real SSRF (private IP) must record SignalBlock in intercept URL path; got signals=%v", rec.signals)
	}
}

// TestInterceptRateLimitNoSignal keeps capacity enforcement separate from
// adaptive threat scoring in both enforcement and audit mode.
func TestInterceptRateLimitNoSignal(t *testing.T) {
	for _, enforce := range []bool{true, false} {
		t.Run(fmt.Sprintf("enforce_%t", enforce), func(t *testing.T) {
			_, _, cfg, _, logger, m := testInterceptSetup(t)
			cfg.Enforce = &enforce
			cfg.FetchProxy.Monitoring.MaxReqPerMinute = 1
			cfg.AdaptiveEnforcement.Enabled = true
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			const targetURL = "https://api.vendor.example/page"
			if result := sc.Scan(t.Context(), targetURL); !result.Allowed {
				t.Fatalf("prime limiter: %s", result.Reason)
			}
			rec := &interceptMockRecorder{}
			calls := 0
			rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader("ordinary page")), Request: r}, nil
			})
			h := newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: logger, Metrics: m, Recorder: rec}, rt)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, targetURL, nil))
			wantStatus, wantCalls := http.StatusOK, 1
			if enforce {
				wantStatus, wantCalls = http.StatusTooManyRequests, 0
			}
			if w.Code != wantStatus || calls != wantCalls {
				t.Fatalf("status=%d upstream=%d want %d/%d", w.Code, calls, wantStatus, wantCalls)
			}
			for _, sig := range rec.signals {
				if sig == session.SignalBlock || sig == session.SignalWarning || sig == session.SignalNearMiss {
					t.Errorf("rate limit must neither raise nor lower threat score: signals=%v", rec.signals)
				}
			}
			if rec.cleanCalled {
				t.Error("rate limit must not lower the threat score")
			}
		})
	}
}

// failingInterceptResolver fails every lookup so the test does not depend on
// how the host resolver treats reserved names.
type failingInterceptResolver struct{}

func (failingInterceptResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}
