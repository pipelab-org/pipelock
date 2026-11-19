// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestRequiredReceiptCallerCancellationDoesNotRecordFailure(t *testing.T) {
	cfg := config.Defaults()
	cfg.FlightRecorder.RequireReceipts = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	p := &Proxy{metrics: metrics.New()}
	p.cfgPtr.Store(cfg)
	e := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, Principal: coverageTestPrincipal, Actor: coverageTestActor, Metrics: p.metrics,
	})
	if e == nil || e.InitError() != nil {
		t.Fatalf("receipt emitter initialization failed: %v", e.InitError())
	}
	p.receiptEmitterPtr.Store(e)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := p.emitRequiredReceipt(receipt.EmitOpts{
		ContentScanContext: ctx,
		ActionID:           receipt.NewActionID(),
		Verdict:            config.ActionAllow,
		Transport:          TransportForward,
		Method:             http.MethodPost,
		Target:             "http://peer.vendor.example/update",
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("required emission returned %v, want caller cancellation", err)
	}
	if err := e.HealthError(); err != nil {
		t.Fatalf("caller cancellation changed emitter health: %v", err)
	}
	assertMetricsNotContain(t, p.metrics, `pipelock_receipt_emit_failures_total{reason="content"} 1`)
	assertMetricsNotContain(t, p.metrics, `pipelock_required_receipt_blocks_total{reason="emit_error",transport="forward"} 1`)
}

func assertMetricsContain(t *testing.T, m *metrics.Metrics, want string) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, line := range strings.Split(body, "\n") {
		if line == want {
			return
		}
	}
	t.Fatalf("missing metric line %q:\n%s", want, body)
}

func assertMetricsNotContain(t *testing.T, m *metrics.Metrics, unwanted string) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, line := range strings.Split(body, "\n") {
		if line == unwanted {
			t.Fatalf("unexpected metric line %q:\n%s", unwanted, body)
		}
	}
}
