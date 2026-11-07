// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
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
