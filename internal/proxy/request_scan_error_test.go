// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestHeaderScanErrorRefusedAcrossHTTPConsumers(t *testing.T) {
	for _, kind := range []string{"forward", "connect", "intercept", "websocket"} {
		t.Run(kind, func(t *testing.T) {
			cfg := testScannerConfig()
			cfg.Internal = nil
			cfg.Enforce = new(false)
			cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.ScanHeaders = true
			cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
			cfg.RequestBodyScanning.Action = config.ActionWarn
			cfg.WebSocketProxy.Enabled = true
			p := newTestProxyWithConfig(t, cfg)
			var calls atomic.Int32
			rt := forwardBoundaryRoundTripper(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, fmt.Errorf("unverified headers reached upstream")
			})
			p.client = &http.Client{Transport: rt}
			refused := false
			for checkpoint := int32(1); checkpoint <= 64; checkpoint++ {
				base, cancel := context.WithCancel(t.Context())
				ctx := &bodyScanCheckpointContext{Context: base, cancel: cancel, after: checkpoint}
				target, method := "http://api.vendor.example/ordinary", http.MethodGet
				switch kind {
				case "connect":
					target, method = "http://api.vendor.example:443", http.MethodConnect
				case "websocket":
					target = "/ws?url=ws://api.vendor.example/events"
				}
				req := httptest.NewRequestWithContext(ctx, method, target, nil)
				if kind == "connect" {
					req.URL.Scheme = ""
					req.URL.Host = "api.vendor.example:443"
					req.Host = "api.vendor.example:443"
				}
				req.Header.Set("Authorization", "Bearer ordinary")
				w := httptest.NewRecorder()
				switch kind {
				case "forward":
					p.handleForwardHTTP(w, req)
				case "connect":
					p.handleConnect(w, req)
				case "intercept":
					h := newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: p.ScannerPtr().Load(), Logger: audit.NewNop(), Metrics: p.metrics, ClientIP: "192.0.2.1", RequestID: "header-scan-error", Proxy: p}, rt)
					h.ServeHTTP(w, req)
				case "websocket":
					p.handleWebSocket(w, req)
				}
				cancelledDuringRequest := base.Err() != nil
				cancel()
				if w.Code == http.StatusServiceUnavailable && w.Header().Get("X-Pipelock-Block-Reason") == "parse_error" {
					if !cancelledDuringRequest || calls.Load() != 0 || !strings.Contains(w.Body.String(), scanner.ErrTextDLPIncomplete.Error()) {
						t.Fatalf("unverified header refusal: canceled=%v upstream=%d body=%s", cancelledDuringRequest, calls.Load(), w.Body.String())
					}
					refused = true
					break
				}
				if calls.Load() != 0 {
					t.Fatalf("unverified headers reached upstream at checkpoint %d", checkpoint)
				}
			}
			if !refused {
				t.Fatal("no incomplete header scan refusal reached")
			}
		})
	}
}

func TestReverseRequestScanErrorPreservesRefusalEvidence(t *testing.T) {
	for _, headers := range []bool{false, true} {
		t.Run(fmt.Sprintf("headers_%t", headers), func(t *testing.T) {
			cfg := reverseParityBaseConfig(t)
			cfg.Enforce = new(false)
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.ScanHeaders = true
			cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
			cfg.RequestBodyScanning.Action = config.ActionWarn
			var calls atomic.Int32
			rp, p, _ := newReverseParityHarness(t, cfg, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
			rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(rph.emitter)
			rp.SetReceiptEmitter(&p.receiptEmitterPtr)
			base, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx := &bodyScanCheckpointContext{Context: base, cancel: cancel, after: 1}
			if headers {
				// Measure the complete URL scan rather than assuming its number
				// of context checks; cancel when the subsequent header scan starts.
				probe := &bodyScanCheckpointContext{Context: t.Context(), after: -1}
				if result := rp.scPtr.Load().ScanTextForDLP(probe, "/ordinary"); !result.Clean {
					t.Fatalf("URL control = %+v", result)
				}
				ctx.after = probe.checks.Load() + 1
			}
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://reverse.example/ordinary", nil)
			if headers {
				req.Header.Set("X-Fixture", "ordinary")
			}
			w := httptest.NewRecorder()
			rp.ServeHTTP(w, req)
			if ctx.Err() == nil || w.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
				t.Fatalf("scan failure: canceled=%v status=%d upstream=%d body=%s", ctx.Err(), w.Code, calls.Load(), w.Body.String())
			}
			var result ReverseProxyBlockResponse
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || !result.Blocked || result.Error == "" || result.Direction != scanDirectionRequest || !strings.Contains(result.BlockReason, scanner.ErrTextDLPIncomplete.Error()) {
				t.Errorf("reverse refusal lost its JSON contract: result=%+v err=%v body=%s", result, err, w.Body.String())
			}
			assertRequestScanErrorHeaders(t, w)
			assertMetricsContain(t, p.metrics, `pipelock_reverse_proxy_requests_total{method="GET",status="503"} 1`)
			assertMetricsContain(t, p.metrics, `pipelock_reverse_proxy_scan_blocked_total{direction="request",reason="scan_error"} 1`)
			assertRequestScanErrorReceipt(t, rph, TransportReverse)
		})
	}
}

func TestFetchHeaderScanErrorPreservesRefusalEvidence(t *testing.T) {
	p, rph := fetchRequireReceiptsLiveProxy(t, func(cfg *config.Config) {
		cfg.Enforce = new(false)
		cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
		cfg.DLP.ScanEnv = false
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.ScanHeaders = true
		cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
		cfg.RequestBodyScanning.Action = config.ActionWarn
	})
	var calls atomic.Int32
	p.client = &http.Client{Transport: forwardBoundaryRoundTripper(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, fmt.Errorf("unverified request reached upstream")
	})}
	// Walk the finite request's cancellation checkpoints to reach the header
	// scan without depending on the URL scanner's implementation details.
	found := false
	for checkpoint := int32(1); checkpoint <= 64; checkpoint++ {
		base, cancel := context.WithCancel(t.Context())
		ctx := &bodyScanCheckpointContext{Context: base, cancel: cancel, after: checkpoint}
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/fetch?url=http://api.vendor.example/ordinary", nil)
		req.Header.Set("X-Fixture", "ordinary")
		w := httptest.NewRecorder()
		p.handleFetch(w, req)
		cancel()
		if w.Code != http.StatusServiceUnavailable {
			continue
		}
		found = true
		var result FetchResponse
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || !result.Blocked || result.URL != "http://api.vendor.example/ordinary" || !strings.Contains(result.BlockReason, scanner.ErrTextDLPIncomplete.Error()) {
			t.Errorf("fetch refusal lost its JSON contract: result=%+v err=%v body=%s", result, err, w.Body.String())
		}
		assertRequestScanErrorHeaders(t, w)
		assertMetricsContain(t, p.metrics, `pipelock_scanner_hits_total{agent="_default",scanner="context"} 1`)
		assertRequestScanErrorReceipt(t, rph, TransportFetch)
		break
	}
	if !found || calls.Load() != 0 {
		t.Fatalf("header scan not refused before forwarding: found=%v upstream=%d", found, calls.Load())
	}
}

func assertRequestScanErrorHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("X-Pipelock-Block-Reason") != "parse_error" {
		t.Errorf("scan error headers = %v", w.Header())
	}
}

func assertRequestScanErrorReceipt(t *testing.T, rph *receiptProxyHelper, transport string) {
	t.Helper()
	r := rph.requireReceipt(t, scanner.ScannerContext)
	if r.ActionRecord.Verdict != config.ActionBlock || r.ActionRecord.Transport != transport || !strings.Contains(r.ActionRecord.Pattern, scanner.ErrTextDLPIncomplete.Error()) {
		t.Errorf("scan error receipt = %+v", r.ActionRecord)
	}
	if r.ActionRecord.ActionID == "" || r.ActionRecord.RequestID == "" {
		t.Errorf("scan error receipt lacks request identity: %+v", r.ActionRecord)
	}
}
