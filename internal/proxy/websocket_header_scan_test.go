// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const wsHeaderVendorPattern = "Vendor Header Token"

func wsHeaderVendorToken() string {
	return "vendor-token-" + "abcdEFGHijkl"
}

func wsHeaderVendorConfig(action string, enforce bool) *config.Config {
	cfg := testScannerConfig()
	cfg.Enforce = new(enforce)
	cfg.WebSocketProxy.Enabled = true
	cfg.RequestBodyScanning.Action = action
	cfg.DLP.ScanEnv = false
	cfg.SessionProfiling.Enabled = false
	cfg.AdaptiveEnforcement.Enabled = false
	cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"127.0.0.1"}}
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:     wsHeaderVendorPattern,
		Regex:    `vendor-token-[A-Za-z0-9]{12}`,
		Severity: config.SeverityHigh,
	})
	return cfg
}

type countingDialer struct{ hits *atomic.Int32 }

func (d countingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.hits.Add(1)
	return nil, errors.New("upstream dial")
}

func TestDLPScanWSHeadersKeepsStoppedFinding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		action  string
		enforce bool
	}{
		{name: "block", action: config.ActionBlock, enforce: true},
		{name: "warn", action: config.ActionWarn, enforce: true},
		{name: "enforce_false", action: config.ActionWarn, enforce: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := wsHeaderVendorConfig(tc.action, tc.enforce)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p := &Proxy{metrics: metrics.New()}
			headers := http.Header{
				"Authorization": {wsHeaderVendorToken()},
				"X-Api-Key":     {"ordinary"},
			}
			kept := false
			for checkpoint := int32(1); checkpoint <= 128; checkpoint++ {
				base, cancel := context.WithCancel(t.Context())
				ctx := &bodyScanCheckpointContext{Context: base, cancel: cancel, after: checkpoint}
				blocked, hard, action, _, pattern, err := p.dlpScanWSHeaders(ctx, headers, sc, cfg, "wss://api.vendor.example/events", audit.LogContext{})
				stopped := base.Err() != nil
				cancel()
				if !stopped {
					if !strings.Contains(pattern, wsHeaderVendorPattern) {
						t.Fatalf("fixture must match, pattern=%q", pattern)
					}
					break
				}
				if !strings.Contains(pattern, wsHeaderVendorPattern) || err != nil || !blocked {
					continue
				}
				if !hard && (action != config.ActionBlock || !tc.enforce) {
					t.Fatalf("checkpoint %d: stopped finding would be forwarded: hard=%v action=%s pattern=%q", checkpoint, hard, action, pattern)
				}
				kept = true
				break
			}
			if !kept {
				t.Fatal("no stopped header scan kept the credential pattern")
			}
		})
	}
}

func TestDLPScanWSHeadersIncompleteWithoutFinding(t *testing.T) {
	cfg := wsHeaderVendorConfig(config.ActionWarn, false)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p := &Proxy{metrics: metrics.New()}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	blocked, _, _, _, pattern, err := p.dlpScanWSHeaders(ctx, http.Header{"Authorization": {"Bearer ordinary"}}, sc, cfg, "wss://api.vendor.example/events", audit.LogContext{})
	if blocked || pattern != "" || !errors.Is(err, scanner.ErrTextDLPIncomplete) {
		t.Fatalf("incomplete scan without a finding: blocked=%v pattern=%q err=%v", blocked, pattern, err)
	}
}

func TestWebSocketHandshakeHeaderScanStopRecordsTheDecision(t *testing.T) {
	client, proxyStop, complete := "client", "proxy", "complete"
	cases := []wsHeaderScanCase{
		{name: "block_stopped", action: config.ActionBlock, enforce: true, stop: client, header: "Authorization", value: wsHeaderVendorToken(), wantPattern: true},
		{name: "warn_stopped", action: config.ActionWarn, enforce: true, stop: client, header: "Authorization", value: wsHeaderVendorToken(), wantPattern: true},
		{name: "enforce_false_stopped", action: config.ActionWarn, enforce: false, stop: client, header: "Authorization", value: wsHeaderVendorToken(), wantPattern: true},
		{name: "protocol_offer_stopped", action: config.ActionWarn, enforce: false, stop: client, header: "Sec-WebSocket-Protocol", value: "chat, " + wsHeaderVendorToken(), wantPattern: true},
		{name: "proxy_stop_with_finding", action: config.ActionWarn, enforce: false, stop: proxyStop, header: "Authorization", value: wsHeaderVendorToken(), wantPattern: true},
		{name: "client_cancel_clean", action: config.ActionWarn, enforce: false, stop: client, header: "Authorization", value: "Bearer ordinary", wantCancel: true},
		{name: "proxy_stop_clean", action: config.ActionWarn, enforce: false, stop: proxyStop, header: "Authorization", value: "Bearer ordinary", wantScanErr: true},
		{name: "completed_block", action: config.ActionBlock, enforce: true, stop: complete, header: "Authorization", value: wsHeaderVendorToken(), wantPattern: true},
		{name: "completed_warn", action: config.ActionWarn, enforce: true, stop: complete, header: "Authorization", value: wsHeaderVendorToken(), wantContinue: true},
		{name: "completed_audit", action: config.ActionWarn, enforce: false, stop: complete, header: "Authorization", value: wsHeaderVendorToken(), wantContinue: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := wsHeaderVendorConfig(tc.action, tc.enforce)
			logger, logs := newCancelAuditLogger(t)
			p := newTestProxyWithConfig(t, cfg)
			p.logger = logger
			var dials atomic.Int32
			p.dialer = countingDialer{hits: &dials}
			target := "ws://api.vendor.example/events"
			checkpoint := int32(0)
			if tc.stop != complete {
				var found bool
				for step := int32(1); step <= 256; step++ {
					logs.Reset()
					dials.Store(0)
					w := httptest.NewRecorder()
					req := wsHeaderScanRequest(t, tc.stop, step, target, tc.header, tc.value)
					p.handleWebSocket(w, req)
					if req.Context().Err() == nil {
						continue
					}
					if wsHeaderScanDecisionReached(tc, w, logs.String(), dials.Load()) {
						checkpoint = step
						found = true
						break
					}

				}
				if !found {
					t.Fatal("no checkpoint reached the handshake header decision")
				}
			}
			logs.Reset()
			dials.Store(0)
			rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(rph.emitter)
			w := httptest.NewRecorder()
			p.handleWebSocket(w, wsHeaderScanRequest(t, tc.stop, checkpoint, target, tc.header, tc.value))
			assertWSHeaderScanDecision(t, tc, w, logs.String(), dials.Load(), rph)
		})
	}
}

func wsHeaderScanRequest(t *testing.T, stop string, checkpoint int32, target, header, value string) *http.Request {
	t.Helper()
	ctx := t.Context()
	if stop != "complete" {
		base, cancel := scanStopContext(t, stop == "client")
		ctx = &bodyScanCheckpointContext{Context: base, cancel: cancel, after: checkpoint}
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/ws?url="+target, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBs"+"ZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	if header != headerNameWSProtocol {
		req.Header.Set(headerNameWSProtocol, "chat")
	}
	req.Header.Set(header, value)
	return req
}

type wsHeaderScanCase struct {
	name         string
	action       string
	enforce      bool
	stop         string
	header       string
	value        string
	wantPattern  bool
	wantCancel   bool
	wantScanErr  bool
	wantContinue bool
}

func wsHeaderScanDecisionReached(tc wsHeaderScanCase, w *httptest.ResponseRecorder, logs string, dials int32) bool {
	if tc.wantPattern {
		return w.Code == http.StatusForbidden && dials == 0 &&
			(strings.Contains(logs, wsHeaderVendorPattern) || strings.Contains(w.Body.String(), wsHeaderVendorPattern))
	}
	if tc.wantCancel {
		return requestCanceledByHeaderScan(logs) && dials == 0
	}
	if tc.wantScanErr {
		return w.Code == http.StatusServiceUnavailable && w.Header().Get("X-Pipelock-Block-Reason") == "parse_error" &&
			strings.Contains(w.Body.String(), scanner.ErrTextDLPIncomplete.Error()) &&
			countAuditEvent(logs, string(audit.EventRequestCanceled)) == 0
	}
	return false
}

func assertWSHeaderScanDecision(t *testing.T, tc wsHeaderScanCase, w *httptest.ResponseRecorder, logs string, dials int32, rph *receiptProxyHelper) {
	t.Helper()
	receipts := rph.findReceipts(t)
	switch {
	case tc.wantPattern:
		if dials != 0 || w.Code != http.StatusForbidden || w.Header().Get("X-Pipelock-Block-Reason") == "" {
			t.Fatalf("finding was forwarded: dials=%d status=%d headers=%v body=%s", dials, w.Code, w.Header(), w.Body.String())
		}
		if !strings.Contains(logs, wsHeaderVendorPattern) || countAuditEvent(logs, "ws_blocked") == 0 {
			t.Fatalf("block record lost the pattern: %s", logs)
		}
		if countAuditEvent(logs, string(audit.EventRequestCanceled)) != 0 {
			t.Fatalf("finding recorded as a cancellation: %s", logs)
		}
		found := false
		for _, got := range receipts {
			if got.ActionRecord.Verdict != config.ActionBlock {
				continue
			}
			if !strings.Contains(got.ActionRecord.Pattern, wsHeaderVendorPattern) || got.ActionRecord.Transport != TransportWS {
				t.Fatalf("block receipt lost the pattern: %+v", got.ActionRecord)
			}
			found = true
		}
		if !found {
			t.Fatal("finding produced no block receipt")
		}
	case tc.wantCancel:
		if dials != 0 || w.Code != http.StatusServiceUnavailable || w.Header().Get("X-Pipelock-Block-Reason") != "" || !strings.Contains(w.Body.String(), clientCanceledStatusText) {
			t.Fatalf("client cancel was a block: dials=%d status=%d headers=%v body=%s", dials, w.Code, w.Header(), w.Body.String())
		}
		if countAuditEvent(logs, string(audit.EventRequestCanceled)) != 1 || countAuditEvent(logs, "blocked") != 0 || countAuditEvent(logs, "ws_blocked") != 0 {
			t.Fatalf("client cancel audit: %s", logs)
		}
		for _, got := range receipts {
			if got.ActionRecord.Verdict == config.ActionBlock {
				t.Fatalf("client cancel emitted a block receipt: %+v", got.ActionRecord)
			}
		}
	case tc.wantScanErr:
		if dials != 0 || w.Code != http.StatusServiceUnavailable || w.Header().Get("X-Pipelock-Block-Reason") != "parse_error" || !strings.Contains(w.Body.String(), scanner.ErrTextDLPIncomplete.Error()) {
			t.Fatalf("proxy stop was not a scan-error refusal: dials=%d status=%d headers=%v body=%s", dials, w.Code, w.Header(), w.Body.String())
		}
		if countAuditEvent(logs, "blocked") == 0 || countAuditEvent(logs, string(audit.EventRequestCanceled)) != 0 {
			t.Fatalf("proxy stop audit: %s", logs)
		}
		for _, got := range receipts {
			if got.ActionRecord.Verdict == config.ActionBlock {
				t.Fatalf("scan error emitted a block receipt: %+v", got.ActionRecord)
			}
		}
	case tc.wantContinue:
		if countAuditEvent(logs, "anomaly") == 0 || !strings.Contains(logs, wsHeaderVendorPattern) || countAuditEvent(logs, "ws_blocked") != 0 {
			t.Fatalf("completed warn did not keep today's anomaly: %s", logs)
		}
		if w.Header().Get("X-Pipelock-Block-Reason") == "dlp_match" {
			t.Fatalf("completed warn was refused as a header finding: status=%d body=%s", w.Code, w.Body.String())
		}
		if dials == 0 {
			t.Fatal("completed warn did not dial upstream")
		}
	default:
		t.Fatal("case has no expected decision")
	}
}

// TestDLPScanWSHeadersStopsAtFirstUnfinishedHeader gives the scan a context
// that has already ended and a credential only in a header scanned later. The
// scan stops at the first unfinished header, so the later header is not
// scanned and the result is an incomplete scan with no finding.
func TestDLPScanWSHeadersStopsAtFirstUnfinishedHeader(t *testing.T) {
	cfg := wsHeaderVendorConfig(config.ActionBlock, true)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p := &Proxy{metrics: metrics.New()}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	headers := http.Header{
		"Authorization": {"Bearer ordinary"},
		"Cookie":        {"session=" + wsHeaderVendorToken()},
	}
	blocked, _, _, _, pattern, err := p.dlpScanWSHeaders(ctx, headers, sc, cfg, "wss://api.vendor.example/events", audit.LogContext{})
	if blocked || pattern != "" || !errors.Is(err, scanner.ErrTextDLPIncomplete) {
		t.Fatalf("scan continued past the unfinished header: blocked=%v pattern=%q err=%v", blocked, pattern, err)
	}
}
