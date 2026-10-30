// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestFetchDeliveryOutcome(t *testing.T) {
	for _, tc := range []struct {
		name, origin, verdict, reason string
		limit                         int
		status                        int
	}{
		{"complete", "text", config.ActionAllow, "complete", -1, http.StatusOK},
		{"empty", "empty", config.ActionAllow, "complete", -1, http.StatusOK},
		{"disconnect", "disconnect", config.ActionWarn, "fetch_failed", -1, http.StatusBadGateway},
		{"truncated upstream", "truncated", config.ActionWarn, "response_read_error", -1, http.StatusBadGateway},
		{"compressed denial", "gzip", config.ActionBlock, "compressed_response", -1, http.StatusForbidden},
		{"closed writer", "text", config.ActionWarn, "delivery_error", 0, http.StatusOK},
		{"partial writer", "text", config.ActionWarn, "delivery_error", 7, http.StatusOK},
		{"denial write error", "gzip", config.ActionBlock, "compressed_response", 7, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.origin == "disconnect" {
					c, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = c.Close()
					return
				}
				w.Header().Set("Content-Type", "text/plain")
				if tc.origin == "truncated" {
					w.Header().Set("Content-Length", "20")
				}
				if tc.origin == "gzip" {
					w.Header().Set("Content-Encoding", "gzip")
				}
				if tc.origin != "empty" {
					_, _ = io.WriteString(w, "ordinary content")
				}
			}))
			defer origin.Close()
			p, helper := fetchRequireReceiptsLiveProxy(t, nil)
			defer p.Close()
			rec := httptest.NewRecorder()
			writer := &deliveryLimitedWriter{ResponseRecorder: rec, remaining: tc.limit}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(origin.URL), nil)
			p.handleFetch(writer, req)
			if rec.Code != tc.status {
				t.Fatalf("status=%d want=%d", rec.Code, tc.status)
			}
			var outcomes, intents int
			for _, rc := range helper.findReceipts(t) {
				ar := rc.ActionRecord
				if ar.DecisionPhase == receipt.DecisionPhaseIntent && ar.Verdict == config.ActionAllow {
					intents++
				}
				if ar.DecisionPhase != receipt.DecisionPhaseOutcome {
					continue
				}
				outcomes++
				captured := 0
				if tc.origin == "text" || tc.origin == "truncated" {
					captured = len("ordinary content")
				}
				want := "status=" + strconv.Itoa(tc.status) + " bytes=" + strconv.Itoa(rec.Body.Len()) + " reason=" + tc.reason + " captured_bytes=" + strconv.Itoa(captured)
				if ar.Verdict != tc.verdict || ar.Pattern != want {
					t.Errorf("outcome verdict=%s pattern=%q want=%s %q", ar.Verdict, ar.Pattern, tc.verdict, want)
				}
				t.Logf("status=%d delivered=%d verdict=%s pattern=%s", rec.Code, rec.Body.Len(), ar.Verdict, ar.Pattern)
			}
			if outcomes != 1 || intents != 1 {
				t.Fatalf("outcomes=%d allow intents=%d", outcomes, intents)
			}
		})
	}
}

type deliveryLimitedWriter struct {
	*httptest.ResponseRecorder
	remaining int
}

func (w *deliveryLimitedWriter) Write(b []byte) (int, error) {
	if w.remaining < 0 {
		return w.ResponseRecorder.Write(b)
	}
	n := min(w.remaining, len(b))
	_, _ = w.ResponseRecorder.Write(b[:n])
	w.remaining -= n
	return n, io.ErrClosedPipe
}

func TestFetchDeliveryWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &fetchDeliveryWriter{ResponseWriter: rec}
	w.WriteHeader(http.StatusAccepted)
	n, err := w.Write([]byte("body"))
	if err != nil || n != 4 || w.bytes != 4 || rec.Code != http.StatusAccepted || w.Unwrap() != rec {
		t.Fatalf("write after header: n=%d err=%v bytes=%d status=%d", n, err, w.bytes, rec.Code)
	}
	w.ResponseWriter = shortDeliveryWriter{ResponseWriter: rec}
	n, err = w.Write([]byte("next"))
	if n != 0 || !errors.Is(err, io.ErrShortWrite) || !errors.Is(w.err, io.ErrShortWrite) || w.bytes != 4 {
		t.Fatalf("short write: n=%d err=%v bytes=%d", n, err, w.bytes)
	}
	if err := encodeJSON(httptest.NewRecorder(), http.StatusOK, make(chan int)); err == nil {
		t.Fatal("encoding failure discarded")
	}
}

type shortDeliveryWriter struct{ http.ResponseWriter }

func (shortDeliveryWriter) Write([]byte) (int, error) { return 0, nil }

func TestFetchDeliveryOptionalReceipts(t *testing.T) {
	origin := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ordinary content") }))
	defer origin.Close()
	p, helper := fetchRequireReceiptsLiveProxy(t, func(cfg *config.Config) { cfg.FlightRecorder.RequireReceipts = false })
	defer p.Close()
	rec := httptest.NewRecorder()
	p.handleFetch(&deliveryLimitedWriter{ResponseRecorder: rec, remaining: 0}, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(origin.URL), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("optional mode status=%d", rec.Code)
	}
	for _, r := range helper.findReceipts(t) {
		if r.ActionRecord.DecisionPhase == receipt.DecisionPhaseOutcome {
			t.Fatal("optional mode made outcomes mandatory")
		}
	}
}
