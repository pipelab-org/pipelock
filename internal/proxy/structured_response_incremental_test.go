// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type structuredPausedReader struct {
	ctx     context.Context
	started chan struct{}
	resume  <-chan struct{}
}

func (r structuredPausedReader) Read(p []byte) (int, error) {
	close(r.started)
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	case <-r.resume:
		return copy(p, "x"), io.EOF
	}
}

func TestStructuredResponseSlowCandidatesLeaveSizeExemptCapacity(t *testing.T) {
	cfg := config.Defaults()
	configureStructuredTest(cfg)
	// Four full-ceiling reservations used to consume the entire shared budget.
	cfg.ResponseScanning.SizeExemptScanMaxInflightBytes = 4 * structuredTestCeiling
	var budget sizeExemptScanBudget
	ctx, cancel := context.WithCancel(t.Context())
	resume := make(chan struct{})
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for range 4 {
		started := make(chan struct{})
		wg.Go(func() {
			body, view, release := budget.readStructuredResponse(ctx, "data.vendor.example", []byte("1"), structuredPausedReader{ctx: ctx, started: started, resume: resume}, cfg)
			release()
			if body != nil || view != nil {
				t.Error("non-JSON candidate delivered payload")
			}
		})
		<-started
	}
	slowBytes := budget.inflightBytes.Load()
	body, release, failure := budget.readBoundedSizeExemptResponse("artifact.vendor.example", nil, strings.NewReader("artifact"), cfg.ResponseScanning.SizeExemptScanMaxBytes, cfg.ResponseScanning.SizeExemptScanMaxInflightBytes, sizeRemedies{})
	if failure == nil && budget.inflightBytes.Load() != slowBytes+structuredTestCeiling {
		t.Error("size-exempt read no longer holds its full ceiling reservation")
	}
	release()
	if failure != nil || string(body) != "artifact" {
		t.Errorf("slow candidates exhausted legitimate size-exempt admission: %v", failure)
	}
	close(resume) // Each paused body completes as non-JSON "1x".
	wg.Wait()
	if got := budget.inflightBytes.Load(); got != 0 {
		t.Fatalf("parse failure leaked %d bytes", got)
	}
}

func TestStructuredResponseIncrementalCancellationReturnsBudget(t *testing.T) {
	cfg := config.Defaults()
	configureStructuredTest(cfg)
	var budget sizeExemptScanBudget
	ctx, cancel := context.WithCancel(t.Context())
	started, done := make(chan struct{}), make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() {
		defer close(done)
		body, view, release := budget.readStructuredResponse(ctx, "data.vendor.example", []byte(`{"data":"garden"}`), structuredPausedReader{ctx: ctx, started: started}, cfg)
		release()
		if body != nil || view != nil {
			t.Error("cancelled response retained payload or views")
		}
	}()
	<-started
	if budget.inflightBytes.Load() == 0 {
		t.Fatal("cancellation positive control has no retained bytes")
	}
	cancel()
	<-done
	if got := budget.inflightBytes.Load(); got != 0 {
		t.Fatalf("cancellation leaked %d bytes", got)
	}
}

func TestStructuredResponseIncrementalChargeFailure(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
		limit        int
		body         io.Reader
	}{
		{"initial", "{}", 1, structuredForbiddenReader{t}},
		{"growth", " ", structuredTestCap, io.MultiReader(strings.NewReader(strings.Repeat(" ", structuredTestCap)), structuredForbiddenReader{t})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			configureStructuredTest(cfg)
			cfg.ResponseScanning.SizeExemptScanMaxInflightBytes = tc.limit
			var budget sizeExemptScanBudget
			body, view, release := budget.readStructuredResponse(t.Context(), "data.vendor.example", []byte(tc.prefix), tc.body, cfg)
			release()
			if body != nil || view != nil || budget.inflightBytes.Load() != 0 {
				t.Fatal("failed body charge retained payload or leaked its reservation")
			}
		})
	}
}

func TestStructuredResponseInvalidPrefixStopsRead(t *testing.T) {
	cfg := config.Defaults()
	configureStructuredTest(cfg)
	for _, prefix := range []string{"tx", "fx", "nx", "-x", "1x", `"bad` + string(byte(0)), `{"a":]}`} {
		t.Run(prefix, func(t *testing.T) {
			var budget sizeExemptScanBudget
			body, view, release := budget.readStructuredResponse(t.Context(), "data.vendor.example", []byte(prefix), structuredForbiddenReader{t}, cfg)
			release()
			if body != nil || view != nil || budget.inflightBytes.Load() != 0 {
				t.Fatal("invalid prefix retained payload or reservation")
			}
		})
	}
}

func TestStructuredResponseIncrementalAccountingLifecycle(t *testing.T) {
	cfg := config.Defaults()
	configureStructuredTest(cfg)
	for _, tc := range []struct {
		name    string
		reader  io.Reader
		allowed bool
	}{
		{"success", strings.NewReader(`{"data":"garden"}`), true},
		{"success-one-byte-reads", iotest.OneByteReader(strings.NewReader(`{"data":"garden"}`)), true},
		{"success-data-with-EOF", iotest.DataErrReader(strings.NewReader(`{"data":"garden"}`)), true},
		{"parse-failure", strings.NewReader(`{"data":"garden"} x`), false},
		{"truncation", strings.NewReader(`{"data":"garden`), false},
		{"read-error-after-bytes", io.MultiReader(strings.NewReader(`{"data":"garden"}`), iotest.ErrReader(io.ErrUnexpectedEOF)), false},
		{"ceiling", strings.NewReader(`"` + strings.Repeat("x", structuredTestCeiling) + `"`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var budget sizeExemptScanBudget
			body, view, release := budget.readStructuredResponse(t.Context(), "data.vendor.example", nil, tc.reader, cfg)
			if tc.allowed {
				if view == nil || len(body) == 0 || budget.inflightBytes.Load() != view.account.reserved || budget.inflightBytes.Load() < int64(cap(body)) {
					t.Fatal("successful admission lacks exact retained accounting")
				}
			} else if body != nil || view != nil || budget.inflightBytes.Load() != 0 {
				t.Fatal("refusal retained payload or memory charges")
			}
			release()
			release()
			if budget.inflightBytes.Load() != 0 {
				t.Fatal("release leaked or double-refunded bytes")
			}
		})
	}
}

func TestStructuredResponseInterceptRequiredEvidence(t *testing.T) {
	for _, tc := range []struct {
		name           string
		required, fail bool
	}{
		{"confirmed", true, false},
		{"optional-confirmed", false, false},
		{"receipt-failure-blocks", true, true},
		{"optional-receipt-failure-delivers", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			configureStructuredTest(cfg)
			cfg.FlightRecorder.RequireReceipts = tc.required
			cfg.Internal = nil
			cfg.ApplyDefaults()
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(rph.emitter)
			body := []byte(strings.Repeat(" ", structuredTestCap+1) + `{"data":"garden"}`)
			reached := false
			rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				reached = true // Request admission and its receipt already succeeded.
				if tc.fail {
					if err := rph.rec.Close(); err != nil {
						t.Error(err)
					}
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}, "X-Upstream-Only": {"garden"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
			})
			ic := &InterceptContext{TargetHost: "93.184.216.34", TargetPort: "443", Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: p.metrics, Proxy: p, RequestID: "structured-required"}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://93.184.216.34/data", nil)
			w := httptest.NewRecorder()
			newInterceptHandler(ic, rt).ServeHTTP(w, req)
			if !reached {
				t.Fatal("positive control failed: request did not reach upstream")
			}
			if tc.required && tc.fail {
				if w.Code != http.StatusForbidden || bytes.Contains(w.Body.Bytes(), []byte("garden")) || w.Header().Get("X-Upstream-Only") != "" || w.Header().Get(blockreason.HeaderReason) != string(blockreason.ReceiptEmissionFailed) {
					t.Fatalf("receipt failure leaked payload: status=%d body=%s", w.Code, w.Body.String())
				}
				return
			}
			if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), body) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if tc.fail {
				return // Optional recorder failure still delivered the exact body.
			}
			var evidenceCount int
			for _, r := range rph.findReceipts(t) {
				if r.ActionRecord.Layer == structuredResponseLayer {
					if r.ActionRecord.DecisionPhase != "" || r.ActionRecord.Pattern != structuredResponseEvidence || r.ActionRecord.ParentActionID == "" || r.ActionRecord.Verdict != config.ActionWarn {
						t.Fatalf("structured evidence is not a confirmed partial response decision: %+v", r.ActionRecord)
					}
					if err := receipt.VerifyWithKey(r, rph.pubHex); err != nil {
						t.Fatal(err)
					}
					evidenceCount++
				}
			}
			if evidenceCount != 1 {
				t.Fatalf("got %d structured evidence receipts, want one confirmed decision", evidenceCount)
			}
		})
	}
}
