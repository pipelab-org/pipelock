// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

type reverseFlushErrorWriter struct {
	*httptest.ResponseRecorder
	flushErr error
	setErr   error
	flushes  int
}

func (w *reverseFlushErrorWriter) SetWriteDeadline(time.Time) error { return w.setErr }

func (w *reverseFlushErrorWriter) FlushError() error {
	w.flushes++
	return w.flushErr
}

// TestProgressDeadlineWriter_FlushErrors checks the controller's error path without requiring a write failure.
func TestProgressDeadlineWriter_FlushErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		setErr   error
		flushErr error
		want     error
		flushes  int
	}{
		{"transport", nil, io.ErrClosedPipe, io.ErrClosedPipe, 1},
		{"deadline", io.ErrClosedPipe, nil, io.ErrClosedPipe, 0},
		{"success", nil, nil, nil, 1},
		{"budget", nil, nil, errReverseWriteBudget, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := &reverseFlushErrorWriter{ResponseRecorder: httptest.NewRecorder(), flushErr: tc.flushErr, setErr: tc.setErr}
			pw := &progressDeadlineWriter{ResponseWriter: inner, rc: http.NewResponseController(inner), stall: time.Second, total: time.Minute}
			if tc.name == "budget" {
				pw.end = time.Now().Add(-time.Second)
			}
			if err := http.NewResponseController(pw).Flush(); !errors.Is(err, tc.want) {
				t.Fatalf("Flush = %v, want %v", err, tc.want)
			}
			if inner.flushes != tc.flushes {
				t.Fatalf("flushes = %d, want %d", inner.flushes, tc.flushes)
			}
			pw.Flush()
			if inner.flushes != 2*tc.flushes {
				t.Fatalf("legacy Flush count = %d, want %d", inner.flushes, 2*tc.flushes)
			}
		})
	}
}

// TestReverseOutcomeProgressFlushFailure signs incomplete delivery after a successful buffered body write.
func TestReverseOutcomeProgressFlushFailure(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "2")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(origin.Close)
	u, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.FlightRecorder.RequireReceipts = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: "h", Principal: "local", Actor: "pipelock"})
	var emitterPtr atomic.Pointer[receipt.Emitter]
	emitterPtr.Store(emitter)
	rp := proxy.NewReverseProxy(u, &cfgPtr, &scPtr, audit.NewNop(), metrics.New(), killswitch.New(cfg), nil, nil)
	rp.SetReceiptEmitter(&emitterPtr)
	inner := &reverseFlushErrorWriter{ResponseRecorder: httptest.NewRecorder(), flushErr: io.ErrClosedPipe}
	withWriteProgressDeadline(rp, time.Second, time.Minute).ServeHTTP(inner, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/data", nil))
	if inner.Code != http.StatusOK || inner.Body.String() != "ok" || inner.flushes != 1 {
		t.Fatalf("buffered response: status=%d body=%q flushes=%d", inner.Code, inner.Body.String(), inner.flushes)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	var outcomes int
	for _, ar := range readRuntimeActionRecords(t, dir) {
		if ar.DecisionPhase != receipt.DecisionPhaseOutcome {
			continue
		}
		outcomes++
		if ar.Verdict != config.ActionAllow || ar.Pattern != "status=200 bytes=unknown reason=incomplete bytes_exact=false" {
			t.Fatalf("flush outcome = %+v", ar)
		}
	}
	if outcomes != 1 {
		t.Fatalf("outcomes = %d, want 1", outcomes)
	}
}
