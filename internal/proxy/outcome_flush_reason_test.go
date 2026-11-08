// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestOutcomeFlushRetainsFailureDetails checks that flush errors preserve earlier stream failures.
func TestOutcomeFlushRetainsFailureDetails(t *testing.T) {
	for _, reason := range []string{httpstream.Cancelled, receiptReasonSSEStreamCancelled, "response_scan_error", receiptEmissionFailedLayer, "fetch_failed", "future_failure", receiptReasonExemptOverCapUnscanned} {
		t.Run(reason, func(t *testing.T) {
			tracker := newReverseOutcomeTracker(config.Defaults(), receipt.EmitOpts{})
			tracker.RecordObserved(http.StatusOK, 42, reason, true)
			tracker.RecordFlushError()
			if tracker.status != "200" || tracker.reason != reason || tracker.bytesTransferred != 42 || tracker.bytesExact == nil || !*tracker.bytesExact {
				t.Fatalf("flush replaced status=%q reason=%q bytes=%d", tracker.status, tracker.reason, tracker.bytesTransferred)
			}
		})
	}
}

// TestOutcomeFlushRetainsUpstreamFailure checks upstream failure evidence when delivery also fails.
func TestOutcomeFlushRetainsUpstreamFailure(t *testing.T) {
	for _, surface := range []string{"fetch", "forward", "intercept"} {
		t.Run(surface, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
			t.Cleanup(origin.Close)
			rph := newReceiptProxyHelper(t)
			t.Cleanup(func() { _ = rph.rec.Close() })
			handler := setupFetchProxyWithReceipts(t, rph, func(cfg *config.Config) {
				cfg.APIAllowlist = nil
				cfg.FlightRecorder.RequireReceipts = true
				cfg.ForwardProxy.Enabled = true
			})
			target, reason := origin.URL, "fetch_failed"
			switch surface {
			case "fetch":
				target = "/fetch?url=" + url.QueryEscape(origin.URL)
			case "intercept":
				_, _, cfg, _, logger, m := testInterceptSetup(t)
				cfg.FlightRecorder.RequireReceipts = true
				sc := scanner.MustNew(cfg)
				p, err := New(cfg, logger, sc, m, WithReceiptEmitter(rph.emitter))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				handler = newInterceptHandler(&InterceptContext{Config: cfg, Scanner: sc, Logger: logger, Metrics: m, TargetHost: testLoopbackIP, TargetPort: "443", Proxy: p}, roundTripperFunc(func(*http.Request) (*http.Response, error) {
					return nil, errors.New("upstream unavailable")
				}))
				target, reason = "https://"+testLoopbackIP+"/data", "upstream_error"
			}
			writer := &issuedRedirectFlushWriter{ResponseRecorder: httptest.NewRecorder(), err: io.ErrClosedPipe}
			handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
			if writer.Code != http.StatusBadGateway || writer.Body.Len() == 0 {
				t.Fatalf("missing buffered error response: %d %q", writer.Code, writer.Body.String())
			}
			var found bool
			for _, rcpt := range rph.findReceipts(t) {
				ar := rcpt.ActionRecord
				if ar.DecisionPhase == receipt.DecisionPhaseOutcome {
					found = true
					if !strings.HasPrefix(ar.Pattern, "status=502 bytes=unknown reason="+reason) {
						t.Errorf("flush replaced upstream failure: %q", ar.Pattern)
					}
				}
			}
			if !found {
				t.Fatal("missing outcome")
			}
		})
	}
}

// TestInterceptOutcomeFlushSSEVerdicts preserves inspection evidence when delivery fails.
func TestInterceptOutcomeFlushSSEVerdicts(t *testing.T) {
	const marker = "blocked stream marker"
	for _, tc := range []struct {
		name    string
		body    string
		flush   error
		verdict string
		reason  string
	}{
		{"blocked_failed_flush", marker, io.ErrClosedPipe, config.ActionBlock, LayerSSEStream},
		{"blocked_delivered", marker, nil, config.ActionBlock, LayerSSEStream},
		{"allowed_failed_flush", "ordinary event", io.ErrClosedPipe, config.ActionAllow, receiptReasonIncomplete},
		{"allowed_delivered", "ordinary event", nil, config.ActionAllow, LayerSSEStream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, cfg, _, logger, m := testInterceptSetup(t)
			cfg.FlightRecorder.RequireReceipts = true
			cfg.ResponseScanning.Enabled = true
			cfg.ResponseScanning.SSEStreaming.Enabled = true
			cfg.ResponseScanning.SSEStreaming.Action = config.ActionBlock
			cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{Name: "stream marker", Regex: marker})
			sc := scanner.MustNew(cfg)
			rph := newReceiptProxyHelper(t)
			t.Cleanup(func() { _ = rph.rec.Close() })
			p, err := New(cfg, logger, sc, m, WithReceiptEmitter(rph.emitter))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			handler := newInterceptHandler(&InterceptContext{Config: cfg, Scanner: sc, Logger: logger, Metrics: m, TargetHost: testLoopbackIP, TargetPort: "443", Proxy: p}, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: " + tc.body + "\n\n")), Request: r}, nil
			}))
			rec := httptest.NewRecorder()
			writer := &issuedRedirectFlushWriter{ResponseRecorder: rec, err: tc.flush}
			handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testLoopbackIP+"/events", nil))
			if tc.verdict == config.ActionBlock && strings.Contains(rec.Body.String(), marker) {
				t.Fatalf("blocked event reached client: %q", rec.Body.String())
			}
			if tc.verdict == config.ActionAllow && !strings.Contains(rec.Body.String(), tc.body) {
				t.Fatalf("allowed event not written: %q", rec.Body.String())
			}
			var outcomes int
			for _, rcpt := range rph.findReceipts(t) {
				ar := rcpt.ActionRecord
				if ar.DecisionPhase != receipt.DecisionPhaseOutcome {
					continue
				}
				outcomes++
				if err := receipt.VerifyWithKey(rcpt, rph.pubHex); err != nil {
					t.Fatal(err)
				}
				if ar.Verdict != tc.verdict || ar.Pattern != "status=200 bytes=unknown reason="+tc.reason {
					t.Fatalf("outcome verdict=%s pattern=%q, want %s reason=%s", ar.Verdict, ar.Pattern, tc.verdict, tc.reason)
				}
			}
			if outcomes != 1 {
				t.Fatalf("outcomes = %d, want 1", outcomes)
			}
		})
	}
}

// outcomePanicWriter refuses body delivery after admission.
type outcomePanicWriter struct {
	*httptest.ResponseRecorder
}

func (w *outcomePanicWriter) Write([]byte) (int, error) { panic(http.ErrAbortHandler) }

func (w *outcomePanicWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	panic(http.ErrAbortHandler)
}

// TestOutcomeFlushRetainsPanics checks that outcome recording never swallows a handler abort.
func TestOutcomeFlushRetainsPanics(t *testing.T) {
	for _, surface := range []string{"forward", "fetch", "reverse", "connect", "websocket"} {
		t.Run(surface, func(t *testing.T) {
			handler, rph, target := outcomeFlushHandler(t, surface)
			writer := &outcomePanicWriter{httptest.NewRecorder()}
			func() {
				defer func() {
					got := recover()
					err, ok := got.(error)
					if !ok || !errors.Is(err, http.ErrAbortHandler) {
						t.Errorf("panic = %v, want ErrAbortHandler", got)
					}
				}()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
				if surface == "connect" {
					u, err := url.Parse(target)
					if err != nil {
						t.Fatal(err)
					}
					req.Method, req.Host, req.RequestURI = http.MethodConnect, u.Host, u.Host
					req.URL = &url.URL{Host: u.Host}
				}
				if surface == "websocket" {
					req.Header.Set("Connection", "Upgrade")
					req.Header.Set("Upgrade", "websocket")
					req.Header.Set("Sec-WebSocket-Version", "13")
					req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				}
				handler.ServeHTTP(writer, req)
			}()
			if writer.Flushed || writer.Body.Len() != 0 {
				t.Fatalf("aborted response flushed=%t body=%q", writer.Flushed, writer.Body.String())
			}
			var outcomes int
			for _, rcpt := range rph.findReceipts(t) {
				if rcpt.ActionRecord.DecisionPhase == receipt.DecisionPhaseOutcome {
					outcomes++
					if strings.Contains(rcpt.ActionRecord.Pattern, "reason=complete") {
						t.Fatalf("panic attested complete delivery: %+v", rcpt.ActionRecord)
					}
				}
			}
			if outcomes != 1 {
				t.Fatalf("outcomes = %d, want 1", outcomes)
			}
		})
	}
}
