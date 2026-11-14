// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// nonCoreStripeHalves is a Stripe key split so neither half matches alone.
// Stripe Key is not a core credential, so the configured action still decides.
func nonCoreStripeHalves() (string, string) {
	return "sk_te" + "st_4eC39HqLy", "jWDarjtT1z" + "dp7dc"
}

// coreFloorParts is one cross-request sequence. blockAt is the part that must
// be refused, or -1 when every part is forwarded.
type coreFloorParts struct {
	name    string
	action  string
	enforce bool
	parts   []string
	blockAt int
	// sticky means every part after blockAt is refused too, because the
	// refused bytes stay in the reassembly window.
	sticky bool
}

func coreFloorCases() []coreFloorParts {
	awsPrefix, awsSuffix := pathSecretHalves()
	stripePrefix, stripeSuffix := nonCoreStripeHalves()
	return []coreFloorParts{
		{name: "core_warn_enforce", action: config.ActionWarn, enforce: true, parts: []string{awsPrefix, awsSuffix}, blockAt: 1},
		{name: "core_warn_audit", action: config.ActionWarn, enforce: false, parts: []string{awsPrefix, awsSuffix}, blockAt: 1},
		{name: "noncore_warn", action: config.ActionWarn, enforce: true, parts: []string{stripePrefix, stripeSuffix}, blockAt: -1},
		{name: "noncore_block", action: config.ActionBlock, enforce: true, parts: []string{stripePrefix, stripeSuffix}, blockAt: 1},
		{name: "noncore_block_audit", action: config.ActionBlock, enforce: false, parts: []string{stripePrefix, stripeSuffix}, blockAt: -1},
		{name: "mixed_window", action: config.ActionWarn, enforce: true, parts: []string{stripePrefix, stripeSuffix + awsPrefix, awsSuffix}, blockAt: 2},
		// The refused bytes stay in the window, so the session keeps being
		// refused until the window expires. A configured block has always
		// behaved this way; the core floor now does under warn as well.
		{name: "core_warn_window_stays_refused", action: config.ActionWarn, enforce: true, parts: []string{awsPrefix, awsSuffix, "ordinary-value"}, blockAt: 1, sticky: true},
		{name: "noncore_block_window_stays_refused", action: config.ActionBlock, enforce: true, parts: []string{stripePrefix, stripeSuffix, "ordinary-value"}, blockAt: 1, sticky: true},
	}
}

func coreFloorHTTPConfig(action string, enforce bool) *config.Config {
	cfg := config.Defaults()
	cfg.ApplyDefaults()
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.AdaptiveEnforcement.Enabled = false
	cfg.Taint.Enabled = false
	cfg.RequestBodyScanning.Enabled = false
	cfg.ResponseScanning.Enabled = false
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.Action = action
	cfg.CrossRequestDetection.EntropyBudget.Enabled = false
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
	cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 65536
	cfg.CrossRequestDetection.FragmentReassembly.WindowMinutes = 5
	cfg.Enforce = ptrBool(enforce)
	return cfg
}

func newCoreFloorProxy(t *testing.T, action string, enforce bool) *Proxy {
	t.Helper()
	cfg := coreFloorHTTPConfig(action, enforce)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func assertCoreFloorStatuses(t *testing.T, tc coreFloorParts, statuses []int) {
	t.Helper()
	if len(statuses) != len(tc.parts) {
		t.Fatalf("statuses = %v, want %d parts", statuses, len(tc.parts))
	}
	for i, status := range statuses {
		wantBlock := i == tc.blockAt || (tc.sticky && tc.blockAt >= 0 && i > tc.blockAt)
		blocked := status == http.StatusForbidden
		if blocked != wantBlock {
			t.Fatalf("part %d status = %d, want block=%v", i, status, wantBlock)
		}
	}
}

func TestCoreFloor_FetchReceipt(t *testing.T) {
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)
	cfg := coreFloorHTTPConfig(config.ActionWarn, true)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", logPath, false, true)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(logger.Close)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)
	rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
	p.receiptEmitterPtr.Store(rph.emitter)

	prefix, suffix := pathSecretHalves()
	fetchPart := func(part string) *httptest.ResponseRecorder {
		t.Helper()
		target := upstream.URL + "/collect?p=" + url.QueryEscape(part)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(target), nil)
		req.RemoteAddr = "203.0.113.10:4101"
		rec := httptest.NewRecorder()
		p.handleFetch(rec, req)
		return rec
	}
	if rec := fetchPart(prefix); rec.Code == http.StatusForbidden {
		t.Fatalf("prefix status = %d, want forward", rec.Code)
	}
	rec := fetchPart(suffix)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("completing status = %d, want 403", rec.Code)
	}
	logger.Close()
	logged, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(logged), "cross_request_fragment") || !strings.Contains(string(logged), "core pattern cannot be downgraded") {
		t.Fatalf("audit log = %s, want blocked core fragment", logged)
	}
	got := rph.requireReceipt(t, "cross_request")
	if got.ActionRecord.Verdict != config.ActionBlock || got.ActionRecord.Pattern != "AWS Access ID" {
		t.Fatalf("receipt = %+v, want blocked AWS Access ID", got.ActionRecord)
	}
}

func TestCoreFloor_Fetch(t *testing.T) {
	for _, tc := range coreFloorCases() {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("ok"))
			}))
			t.Cleanup(upstream.Close)
			p := newCoreFloorProxy(t, tc.action, tc.enforce)
			var statuses []int
			for _, part := range tc.parts {
				target := upstream.URL + "/collect?p=" + url.QueryEscape(part)
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(target), nil)
				req.RemoteAddr = "203.0.113.10:4100"
				rec := httptest.NewRecorder()
				p.handleFetch(rec, req)
				statuses = append(statuses, rec.Code)
			}
			assertCoreFloorStatuses(t, tc, statuses)
		})
	}
}

func TestCoreFloor_Forward(t *testing.T) {
	for _, tc := range coreFloorCases() {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("ok"))
			}))
			t.Cleanup(upstream.Close)
			cfg := coreFloorHTTPConfig(tc.action, tc.enforce)
			cfg.ForwardProxy.Enabled = true
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatalf("proxy.New: %v", err)
			}
			t.Cleanup(p.Close)
			proxySrv := httptest.NewServer(p.Handler())
			t.Cleanup(proxySrv.Close)
			proxyURL, err := url.Parse(proxySrv.URL)
			if err != nil {
				t.Fatalf("parse proxy: %v", err)
			}
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
			var statuses []int
			for _, part := range tc.parts {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+"/collect?p="+url.QueryEscape(part), nil)
				if err != nil {
					t.Fatalf("new request: %v", err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("forward %q: %v", part, err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				statuses = append(statuses, resp.StatusCode)
			}
			assertCoreFloorStatuses(t, tc, statuses)
		})
	}
}

func TestCoreFloor_Intercept(t *testing.T) {
	for _, tc := range coreFloorCases() {
		t.Run(tc.name, func(t *testing.T) {
			cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
			sc.Close()
			base := coreFloorHTTPConfig(tc.action, tc.enforce)
			cfg.CrossRequestDetection = base.CrossRequestDetection
			cfg.Enforce = base.Enforce
			cfg.AdaptiveEnforcement.Enabled = false
			cfg.Taint.Enabled = false
			cfg.RequestBodyScanning.Enabled = false
			cfg.ResponseScanning.Enabled = false
			cfg.TLSInterception.Enabled = true
			sc = scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, logger, sc, m)
			if err != nil {
				t.Fatalf("proxy.New: %v", err)
			}
			t.Cleanup(p.Close)
			rt := roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
			})
			var statuses []int
			for _, part := range tc.parts {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testLoopbackIP+"/collect?p="+url.QueryEscape(part), nil)
				if err != nil {
					t.Fatalf("new request: %v", err)
				}
				resp := interceptWithRT(t, cache, pool, cfg, sc, logger, m, rt,
					&InterceptContext{Proxy: p, TargetHost: testLoopbackIP, TargetPort: "443", ClientIP: "203.0.113.10"}, req)
				statuses = append(statuses, resp.StatusCode)
				_ = resp.Body.Close()
			}
			assertCoreFloorStatuses(t, tc, statuses)
		})
	}
}

func TestCoreFloor_Reverse(t *testing.T) {
	for _, tc := range coreFloorCases() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := coreFloorHTTPConfig(tc.action, tc.enforce)
			rp, _, _ := newReverseParityHarness(t, cfg, nil)
			var statuses []int
			for _, part := range tc.parts {
				rec := reverseParityRequest(t, rp, http.MethodGet, "http://reverse.example/collect?p="+url.QueryEscape(part), "203.0.113.10:4200", nil)
				statuses = append(statuses, rec.Code)
			}
			assertCoreFloorStatuses(t, tc, statuses)
		})
	}
}

func TestCoreFloor_WebSocketHandshake(t *testing.T) {
	for _, tc := range coreFloorCases() {
		t.Run(tc.name, func(t *testing.T) {
			backendAddr, backendCleanup := wsEchoServer(t)
			defer backendCleanup()
			proxyAddr, proxyCleanup := setupWSProxy(t, func(cfg *config.Config) {
				base := coreFloorHTTPConfig(tc.action, tc.enforce)
				cfg.CrossRequestDetection = base.CrossRequestDetection
				cfg.Enforce = base.Enforce
				cfg.AdaptiveEnforcement.Enabled = false
				cfg.Taint.Enabled = false
			})
			defer proxyCleanup()
			var statuses []int
			for _, part := range tc.parts {
				conn, err := dialWSConnToTarget(proxyAddr, "ws://"+backendAddr+"/upload/"+part)
				if conn != nil {
					_ = conn.Close()
				}
				if err != nil {
					statuses = append(statuses, http.StatusForbidden)
					continue
				}
				statuses = append(statuses, http.StatusOK)
			}
			assertCoreFloorStatuses(t, tc, statuses)
		})
	}
}

func TestCoreFloor_WebSocketFrames(t *testing.T) {
	for _, tc := range coreFloorCases() {
		t.Run(tc.name, func(t *testing.T) {
			backendAddr, backendCleanup := wsEchoServer(t)
			defer backendCleanup()
			proxyAddr, proxyCleanup := setupWSProxy(t, func(cfg *config.Config) {
				base := coreFloorHTTPConfig(tc.action, tc.enforce)
				cfg.CrossRequestDetection = base.CrossRequestDetection
				cfg.Enforce = base.Enforce
				cfg.AdaptiveEnforcement.Enabled = false
				cfg.Taint.Enabled = false
				cfg.RequestBodyScanning.Enabled = false
				// Per-frame text scanning would see a short split at the frame
				// boundary before fragment reassembly. Leave that path off so
				// this case is decided by the fragment floor.
				cfg.WebSocketProxy.ScanTextFrames = ptrBool(false)
			})
			defer proxyCleanup()
			conn := dialWS(t, proxyAddr, backendAddr)
			defer func() { _ = conn.Close() }()
			var statuses []int
			for _, part := range tc.parts {
				if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(part)); err != nil {
					statuses = append(statuses, http.StatusForbidden)
					continue
				}
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, _, err := wsutil.ReadServerData(conn); err != nil {
					statuses = append(statuses, http.StatusForbidden)
					continue
				}
				statuses = append(statuses, http.StatusOK)
			}
			assertCoreFloorStatuses(t, tc, statuses)
		})
	}
}
