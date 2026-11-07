// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// outcomeDeadlineWriter injects failures at the response-controller boundary.
type outcomeDeadlineWriter struct {
	http.ResponseWriter
	failAt    int
	deadlines []time.Time
	events    []string
	flushErr  error
}

// SetWriteDeadline records setup and reset calls and fails the selected call.
func (w *outcomeDeadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	w.events = append(w.events, "deadline")
	if len(w.deadlines) == w.failAt {
		return io.ErrClosedPipe
	}
	return nil
}

// FlushError records the final flush without hiding its injected error.
func (w *outcomeDeadlineWriter) FlushError() error {
	w.events = append(w.events, "flush")
	return w.flushErr
}

// outcomeUnwrapWriter forces ResponseController to discover the inner writer.
type outcomeUnwrapWriter struct{ http.ResponseWriter }

// Unwrap exposes the deadline and flush methods to ResponseController.
func (w *outcomeUnwrapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// requireOutcomeAbort runs with a server context and verifies net/http's abort sentinel.
func requireOutcomeAbort(t *testing.T, handler http.Handler, w http.ResponseWriter, target string) {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	r = r.WithContext(context.WithValue(r.Context(), http.ServerContextKey, &http.Server{ReadHeaderTimeout: time.Second}))
	defer func() {
		got := recover()
		err, ok := got.(error)
		if !ok || !errors.Is(err, http.ErrAbortHandler) {
			t.Errorf("server abort = %v, want ErrAbortHandler", got)
		}
	}()
	handler.ServeHTTP(w, r)
}

// TestOutcomeFlushDeadlineErrors covers setup and reset failures through Unwrap.
func TestOutcomeFlushDeadlineErrors(t *testing.T) {
	for _, surface := range []string{"forward", "fetch", "reverse", "intercept"} {
		for _, stage := range []string{"setup", "reset"} {
			t.Run(surface+"/"+stage, func(t *testing.T) {
				handler, rph, target := outcomeFlushHandler(t, surface)
				w := &outcomeDeadlineWriter{ResponseWriter: httptest.NewRecorder(), failAt: 1}
				wantEvents := "deadline"
				if stage == "reset" {
					w.failAt = 2
					wantEvents = "deadline,flush,deadline"
				}
				requireOutcomeAbort(t, handler, &outcomeUnwrapWriter{w}, target)
				if got := strings.Join(w.events, ","); got != wantEvents {
					t.Fatalf("controller calls = %s, want %s", got, wantEvents)
				}
				receipts := rph.findReceipts(t)
				var outcomes int
				for _, rcpt := range receipts {
					ar := rcpt.ActionRecord
					if ar.DecisionPhase != receipt.DecisionPhaseOutcome {
						continue
					}
					outcomes++
					if err := receipt.VerifyWithKey(rcpt, rph.pubHex); err != nil {
						t.Fatal(err)
					}
					reason, verdict := receiptReasonIncomplete, config.ActionAllow
					if surface == "fetch" {
						reason, verdict = "delivery_error", config.ActionWarn
					}
					if ar.Verdict != verdict || !strings.Contains(ar.Pattern, "reason="+reason) {
						t.Fatalf("deadline failure outcome = %+v", ar)
					}
					if surface != "fetch" && !strings.Contains(ar.Pattern, "bytes=unknown") {
						t.Fatalf("deadline failure attested bytes: %s", ar.Pattern)
					}
				}
				if outcomes != 1 {
					t.Fatalf("outcomes = %d, want 1", outcomes)
				}
			})
		}
	}
}

// TestOutcomeFlushDefaultTimeout covers programmatic configs without normalization.
func TestOutcomeFlushDefaultTimeout(t *testing.T) {
	for _, seconds := range []int{0, -1, 7} {
		t.Run(strconv.Itoa(seconds), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.ForwardProxy.IdleTimeoutSeconds = seconds
			w := &outcomeDeadlineWriter{ResponseWriter: httptest.NewRecorder()}
			before := time.Now()
			if err := flushResponseBeforeOutcome(&outcomeUnwrapWriter{w}, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), cfg); err != nil {
				t.Fatal(err)
			}
			after := time.Now()
			wantSeconds := seconds
			if wantSeconds <= 0 {
				wantSeconds = config.Defaults().ForwardProxy.IdleTimeoutSeconds
			}
			timeout := time.Duration(wantSeconds) * time.Second
			if len(w.deadlines) != 2 || w.deadlines[0].Before(before.Add(timeout)) || w.deadlines[0].After(after.Add(timeout)) || !w.deadlines[1].IsZero() {
				t.Fatalf("deadlines = %v, want configured/default timeout %s then reset", w.deadlines, timeout)
			}
			if got := strings.Join(w.events, ","); got != "deadline,flush,deadline" {
				t.Fatalf("controller calls = %s", got)
			}
		})
	}
}

// TestInterceptOutcomeFlushAccountsBudget covers both streaming paths and copy failures.
func TestInterceptOutcomeFlushAccountsBudget(t *testing.T) {
	for _, surface := range []string{"exempt", "passthrough"} {
		for _, copyFailure := range []bool{false, true} {
			t.Run(surface+"/copy_error="+strconv.FormatBool(copyFailure), func(t *testing.T) {
				_, _, cfg, _, logger, m := testInterceptSetup(t)
				cfg.FlightRecorder.RequireReceipts = true
				cfg.ResponseScanning.Enabled = true
				cfg.FetchProxy.Monitoring.MaxDataPerMinute = 256
				cfg.TLSInterception.MaxResponseBytes = 32
				if surface == "exempt" {
					cfg.ResponseScanning.ExemptDomains = []string{testLoopbackIP}
				} else {
					cfg.ResponseScanning.SizeExemptDomains = []string{testLoopbackIP}
					cfg.ResponseScanning.UnscannablePassthrough = []config.UnscannablePassthroughEntry{{
						Host: testLoopbackIP, Paths: []string{"/payload"}, ContentTypes: []string{"application/octet-stream"}, Reason: "opaque test artifact", Expires: temporaryExpiryDate(config.MaxUnscannablePassthroughHorizon),
					}}
				}
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				target := "https://" + testLoopbackIP + "/payload"
				if result := sc.Scan(t.Context(), target); !result.Allowed {
					t.Fatalf("initial request refused: %+v", result)
				}
				rph := newReceiptProxyHelper(t)
				t.Cleanup(func() { _ = rph.rec.Close() })
				p, err := New(cfg, logger, sc, m, WithReceiptEmitter(rph.emitter))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				payload := strings.Repeat("ordinary response ", 32)
				handler := newInterceptHandler(&InterceptContext{Config: cfg, Scanner: sc, Logger: logger, Metrics: m, TargetHost: testLoopbackIP, TargetPort: "443", Proxy: p}, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					var body io.Reader = strings.NewReader(payload)
					if copyFailure {
						body = io.MultiReader(body, iotest.ErrReader(io.ErrUnexpectedEOF))
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/octet-stream"}, "Content-Disposition": {`attachment; filename="payload.bin"`}}, ContentLength: int64(len(payload)), Body: io.NopCloser(body), Request: r}, nil
				}))
				rec := httptest.NewRecorder()
				w := &outcomeDeadlineWriter{ResponseWriter: rec, flushErr: io.ErrClosedPipe}
				requireOutcomeAbort(t, handler, &outcomeUnwrapWriter{w}, target)
				if rec.Code != http.StatusOK || rec.Body.String() != payload {
					t.Fatalf("streamed status=%d bytes=%d, want 200 and %d", rec.Code, rec.Body.Len(), len(payload))
				}
				if !strings.Contains(strings.Join(w.events, ","), "flush") {
					t.Fatal("final flush not attempted")
				}
				result := sc.Scan(t.Context(), target)
				if result.Allowed || result.Scanner != scanner.ScannerDataBudget {
					t.Fatalf("failed flush did not consume streamed data budget: %+v", result)
				}
				if !copyFailure {
					statsWriter := httptest.NewRecorder()
					m.StatsHandler().ServeHTTP(statsWriter, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil))
					var stats struct {
						Requests struct {
							Allowed int64 `json:"allowed"`
						} `json:"requests"`
					}
					if err := json.Unmarshal(statsWriter.Body.Bytes(), &stats); err != nil {
						t.Fatal(err)
					}
					if stats.Requests.Allowed != 1 {
						t.Fatalf("allowed requests = %d, want 1 before final-flush abort", stats.Requests.Allowed)
					}
				}
				var outcomes int
				var passthroughSeen bool
				for _, rcpt := range rph.findReceipts(t) {
					if rcpt.ActionRecord.Layer == "unscannable_passthrough" {
						passthroughSeen = true
					}
					if rcpt.ActionRecord.DecisionPhase == receipt.DecisionPhaseOutcome {
						outcomes++
						wantReason := receiptReasonIncomplete
						if surface == "exempt" && !copyFailure {
							wantReason = receiptReasonExemptOverCapUnscanned
						}
						if !strings.Contains(rcpt.ActionRecord.Pattern, "reason="+wantReason) {
							t.Fatalf("failed delivery outcome = %+v", rcpt.ActionRecord)
						}
					}
				}
				if surface == "passthrough" && !passthroughSeen {
					t.Fatal("test did not reach the unscannable passthrough stream")
				}
				if outcomes != 1 {
					t.Fatalf("outcomes = %d, want 1", outcomes)
				}
			})
		}
	}
}

// TestReverseBufferedOutcomeFraming checks complete bodies and HTTP framing exclusions.
func TestReverseBufferedOutcomeFraming(t *testing.T) {
	for _, tc := range []struct {
		name, method         string
		status               int
		required, wantLength bool
	}{
		{"clean", http.MethodGet, http.StatusOK, true, true},
		{"empty", http.MethodGet, http.StatusOK, true, true},
		{"head", http.MethodHead, http.StatusOK, true, false},
		{"informational", http.MethodGet, http.StatusEarlyHints, true, false},
		{"no_content", http.MethodGet, http.StatusNoContent, true, false},
		{"receipts_off", http.MethodGet, http.StatusOK, false, false},
		{"streamed_media", http.MethodGet, http.StatusOK, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.FlightRecorder.RequireReceipts = tc.required
			cfg.ResponseScanning.Enabled = true
			cfg.MediaPolicy.Enabled = ptrBool(false)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			var cfgPtr atomic.Pointer[config.Config]
			var scPtr atomic.Pointer[scanner.Scanner]
			cfgPtr.Store(cfg)
			scPtr.Store(sc)
			target, err := url.Parse("http://api.vendor.example")
			if err != nil {
				t.Fatal(err)
			}
			rp := NewReverseProxy(target, &cfgPtr, &scPtr, audit.NewNop(), metrics.New(), killswitch.New(cfg), nil, nil)
			payload := "ordinary response"
			if tc.name == "empty" || tc.method == http.MethodHead || tc.status < http.StatusOK || tc.status == http.StatusNoContent {
				payload = ""
			}
			resp := &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"text/plain"}}, ContentLength: -1, Body: io.NopCloser(strings.NewReader(payload)), Request: httptest.NewRequestWithContext(t.Context(), tc.method, target.String(), nil)}
			if tc.name == "streamed_media" {
				resp.Header.Set("Content-Type", "audio/mpeg")
			}
			if err := rp.modifyResponse(resp); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.status {
				t.Fatalf("status=%d, want %d", resp.StatusCode, tc.status)
			}
			if tc.wantLength {
				if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(payload)) {
					t.Fatalf("Content-Length=%q, want %d", got, len(payload))
				}
			} else if got := resp.Header.Get("Content-Length"); got != "" {
				t.Fatalf("excluded response acquired Content-Length=%q", got)
			}
			if tc.name == "streamed_media" && resp.ContentLength != -1 {
				t.Fatal("unknown-length media was buffered or given an exact length")
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil || string(body) != payload {
				t.Fatalf("body=%q err=%v, want %q", body, err, payload)
			}
		})
	}
}
