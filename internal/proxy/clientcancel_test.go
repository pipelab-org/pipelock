// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// cancelOnFirstRead cancels ctx on the first read, then returns the payload.
// The URL admission therefore sees a live context, and the body scan sees
// context.Canceled.
type cancelOnFirstRead struct {
	cancel func()
	data   []byte
	off    int
}

func (c *cancelOnFirstRead) Read(p []byte) (int, error) {
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.off >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(p, c.data[c.off:])
	c.off += n
	return n, nil
}

func countAuditEvent(raw, event string) int {
	n := 0
	needle := `"event":"` + event + `"`
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, needle) {
			n++
		}
	}
	return n
}

func metricsText(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

func newCancelAuditLogger(t *testing.T) (*audit.Logger, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })
	return logger, &logs
}

func cancelTestConfig() *config.Config {
	cfg := testScannerConfig()
	cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
	cfg.DLP.ScanEnv = false
	return cfg
}

func countingRoundTrip(hits *atomic.Int32) http.RoundTripper {
	return forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
		hits.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    r,
		}, nil
	})
}

func postCancelBody(ctx context.Context, payload []byte, cancel context.CancelFunc) *http.Request {
	body := &cancelOnFirstRead{cancel: cancel, data: payload}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "http://api.vendor.example/v1", body)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(payload))
	return req
}

func assertClientCancel(t *testing.T, logs string, metricBody string, hits int32, status int, body string) {
	t.Helper()
	if hits != 0 {
		t.Fatalf("upstream hits = %d, want 0", hits)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body %s", status, body)
	}
	if !strings.Contains(body, clientCanceledStatusText) {
		t.Fatalf("body = %q, want %q", body, clientCanceledStatusText)
	}
	if countAuditEvent(logs, "blocked") != 0 {
		t.Fatalf("client cancel logged a block: %s", logs)
	}
	if countAuditEvent(logs, "request_canceled") != 1 {
		t.Fatalf("cancellation events = %d, want 1: %s", countAuditEvent(logs, "request_canceled"), logs)
	}
	if strings.Contains(metricBody, `result="blocked"`) || strings.Contains(metricBody, "scan_blocked_total") || strings.Contains(metricBody, "tls_request_blocked_total") {
		t.Fatalf("client cancel counted a block:\n%s", metricBody)
	}
}

func TestClientCancelMidBodyScanNotBlocked(t *testing.T) {
	payload := []byte(`{"note":"ordinary neutral text"}`)
	t.Run("forward", func(t *testing.T) {
		cfg := cancelTestConfig()
		logger, logs := newCancelAuditLogger(t)
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		m := metrics.New()
		p, err := New(cfg, logger, sc, m)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		var hits atomic.Int32
		p.client = &http.Client{Transport: countingRoundTrip(&hits)}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := httptest.NewRecorder()
		p.handleForwardHTTP(w, postCancelBody(ctx, payload, cancel))
		assertClientCancel(t, logs.String(), metricsText(t, m), hits.Load(), w.Code, w.Body.String())
	})
	t.Run("intercept", func(t *testing.T) {
		cfg := cancelTestConfig()
		logger, logs := newCancelAuditLogger(t)
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		m := metrics.New()
		p, err := New(cfg, logger, sc, m)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		var hits atomic.Int32
		rt := countingRoundTrip(&hits)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := httptest.NewRecorder()
		newInterceptHandler(&InterceptContext{
			TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc,
			Logger: logger, Metrics: m, ClientIP: "192.0.2.1", RequestID: "cancel-body", Proxy: p,
		}, rt).ServeHTTP(w, postCancelBody(ctx, payload, cancel))
		assertClientCancel(t, logs.String(), metricsText(t, m), hits.Load(), w.Code, w.Body.String())
	})
	t.Run("reverse", func(t *testing.T) {
		cfg := cancelTestConfig()
		logger, logs := newCancelAuditLogger(t)
		var hits atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(upstream.Close)
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		m := metrics.New()
		p, err := New(cfg, logger, sc, m)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		upstreamURL, err := url.Parse(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		rp := NewReverseProxy(upstreamURL, p.ConfigPtr(), p.ScannerPtr(), logger, m, nil, nil, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req := postCancelBody(ctx, payload, cancel)
		req.URL.Path = "/v1"
		req.Host = upstreamURL.Host
		w := httptest.NewRecorder()
		rp.ServeHTTP(w, req)
		assertClientCancel(t, logs.String(), metricsText(t, m), hits.Load(), w.Code, w.Body.String())
	})
	t.Run("fetch has no body", func(t *testing.T) {
		cfg := cancelTestConfig()
		logger, logs := newCancelAuditLogger(t)
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		m := metrics.New()
		p, err := New(cfg, logger, sc, m)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		var hits atomic.Int32
		p.client = &http.Client{Transport: countingRoundTrip(&hits)}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/fetch?url=http://api.vendor.example/ordinary", nil)
		w := httptest.NewRecorder()
		p.handleFetch(w, req)
		assertClientCancel(t, logs.String(), metricsText(t, m), hits.Load(), w.Code, w.Body.String())
	})
}

func TestDeadlineAndLiveIncompleteScanStillBlocked(t *testing.T) {
	cfg := cancelTestConfig()
	logger, logs := newCancelAuditLogger(t)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var hits atomic.Int32
	p.client = &http.Client{Transport: countingRoundTrip(&hits)}

	t.Run("deadline exceeded", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "http://api.vendor.example/v1", strings.NewReader(`{"note":"ordinary neutral text"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		p.handleForwardHTTP(w, req)
		if hits.Load() != 0 || w.Code == http.StatusOK {
			t.Fatalf("deadline scan was forwarded: hits=%d status=%d body=%s", hits.Load(), w.Code, w.Body.String())
		}
		if countAuditEvent(logs.String(), "blocked") == 0 || countAuditEvent(logs.String(), "request_canceled") != 0 {
			t.Fatalf("deadline scan audit: %s", logs.String())
		}
		if !strings.Contains(metricsText(t, m), `result="blocked"`) {
			t.Fatal("deadline scan was not counted as a block")
		}
	})

	t.Run("live client incomplete injection", func(t *testing.T) {
		beforeBlocks := countAuditEvent(logs.String(), "blocked")
		text := "ordinary neutral text"
		for range 6 {
			text = base64.StdEncoding.EncodeToString([]byte(text))
		}
		encoded, err := json.Marshal(map[string]string{"text": text})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://api.vendor.example/v1", bytes.NewReader(encoded))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		p.handleForwardHTTP(w, req)
		if hits.Load() != 0 || w.Code == http.StatusOK {
			t.Fatalf("incomplete scan was forwarded: hits=%d status=%d body=%s", hits.Load(), w.Code, w.Body.String())
		}
		if countAuditEvent(logs.String(), "blocked") <= beforeBlocks || countAuditEvent(logs.String(), "request_canceled") != 0 {
			t.Fatalf("live incomplete audit: %s", logs.String())
		}
	})
}

func TestFindingBeforeCancelStillRecorded(t *testing.T) {
	cfg := cancelTestConfig()
	logger, logs := newCancelAuditLogger(t)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var hits atomic.Int32
	p.client = &http.Client{Transport: countingRoundTrip(&hits)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	payload := []byte(`{"note":"` + fakeAPIKey() + `"}`)
	w := httptest.NewRecorder()
	p.handleForwardHTTP(w, postCancelBody(ctx, payload, cancel))
	if hits.Load() != 0 || w.Code == http.StatusOK {
		t.Fatalf("finding was forwarded: hits=%d status=%d body=%s", hits.Load(), w.Code, w.Body.String())
	}
	raw := logs.String()
	if countAuditEvent(raw, "body_dlp") == 0 || countAuditEvent(raw, "blocked") == 0 {
		t.Fatalf("finding was not recorded: %s", raw)
	}
	if countAuditEvent(raw, "request_canceled") != 0 {
		t.Fatalf("finding was rewritten as a cancellation: %s", raw)
	}
}

func TestRequestClientCanceledCause(t *testing.T) {
	plain := func(parent context.Context) context.Context {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx
	}
	withCause := func(parent context.Context, cause error) context.Context {
		ctx, cancel := context.WithCancelCause(parent)
		cancel(cause)
		return ctx
	}
	inTunnel := func(tunnel context.Context) context.Context {
		ic := &InterceptContext{}
		return plain(ic.tunnelBaseContext(tunnel)(nil))
	}
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancelExpired()

	tests := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{"live", context.Background(), false},
		{"deadline", expired, false},
		{"client went away", plain(context.Background()), true},
		{"license revoked", withCause(context.Background(), errAgentLicenseRevoked), false},
		{"request under a revoked license", plain(withCause(context.Background(), errAgentLicenseRevoked)), false},
		{"tunnel still open", inTunnel(context.Background()), true},
		{"tunnel closed normally", inTunnel(plain(context.Background())), true},
		{"tunnel ended by the airlock", inTunnel(withCause(context.Background(), errAirlockTerminated)), false},
		{"tunnel deadline", inTunnel(expired), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestClientCanceled(tt.ctx); got != tt.want {
				t.Fatalf("requestClientCanceled = %v, want %v", got, tt.want)
			}
		})
	}
	var missing context.Context
	if requestClientCanceled(missing) {
		t.Fatal("nil context reported as a client cancellation")
	}
}

func TestClientCancelDoesNotRaiseSessionScore(t *testing.T) {
	cfg := cancelTestConfig()
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 100
	cfg.SessionProfiling.DomainBurst = 100
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 600
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = adaptiveTestThreshold
	cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0
	cfg.WebSocketProxy.Enabled = true
	// Header scanning is on by default. On CONNECT it runs before the URL
	// cancellation return and would itself refuse a context that is already
	// canceled, so the score check would never reach that return.
	cfg.RequestBodyScanning.ScanHeaders = false
	logger, logs := newCancelAuditLogger(t)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	p.client = &http.Client{Transport: countingRoundTrip(new(atomic.Int32))}

	scoreOf := func(req *http.Request) float64 {
		t.Helper()
		sm := p.sessionMgrPtr.Load()
		if sm == nil {
			t.Fatal("session manager missing")
		}
		clientIP, _ := requestMeta(req)
		rec := sm.GetOrCreate(responseTaintSessionKey(cfg, "", clientIP, ""))
		if rec == nil {
			t.Fatal("session missing")
		}
		return rec.ThreatScore()
	}

	t.Run("forward", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://api.vendor.example/ordinary", nil)
		before := scoreOf(req)
		w := httptest.NewRecorder()
		p.handleForwardHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), clientCanceledStatusText) {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		if score := scoreOf(req); score != before {
			t.Fatalf("forward cancel threat score = %v, want %v", score, before)
		}
	})
	t.Run("fetch", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/fetch?url=http://api.vendor.example/ordinary", nil)
		before := scoreOf(req)
		w := httptest.NewRecorder()
		p.handleFetch(w, req)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), clientCanceledStatusText) {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		if score := scoreOf(req); score != before {
			t.Fatalf("fetch cancel threat score = %v, want %v", score, before)
		}
	})
	t.Run("connect", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodConnect, "http://api.vendor.example:443", nil)
		req.Host = "api.vendor.example:443"
		before := scoreOf(req)
		w := httptest.NewRecorder()
		p.handleConnect(w, req)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), clientCanceledStatusText) {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		if score := scoreOf(req); score != before {
			t.Fatalf("connect cancel threat score = %v, want %v", score, before)
		}
	})
	t.Run("intercept", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "https://api.vendor.example/ordinary", nil)
		before := scoreOf(req)
		clientIP, _ := requestMeta(req)
		w := httptest.NewRecorder()
		newInterceptHandler(&InterceptContext{
			TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc,
			Logger: logger, Metrics: m, ClientIP: clientIP, RequestID: "cancel-score", Proxy: p,
		}, p.client.Transport).ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), clientCanceledStatusText) {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		if score := scoreOf(req); score != before {
			t.Fatalf("intercept cancel threat score = %v, want %v", score, before)
		}
	})
	if countAuditEvent(logs.String(), "blocked") != 0 {
		t.Fatalf("cancel logged a block: %s", logs.String())
	}
}
