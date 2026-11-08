// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestWatchRequestCoverageOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*config.Config)
		encoding  string
		refuse    bool
	}{
		{name: "default body limit", configure: func(c *config.Config) { c.RequestBodyScanning.MaxBodyBytes = 0 }},
		{name: "redaction unavailable", configure: applyRedactionTestProfile, refuse: true},
		{name: "A2A encoded body", configure: func(c *config.Config) { c.RequestBodyScanning.Enabled = false; c.A2AScanning.Enabled = true }, encoding: "unknown", refuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.WatchOnly = true
			cfg.RequestBodyScanning.Enabled = true
			tc.configure(cfg)
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			const payload = `{"text":"ordinary message"}`
			closed := false
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.vendor.example/message:send", nil)
			r.Body = &watchCoverageBody{Reader: strings.NewReader(payload), onClose: func() { closed = true }}
			r.Header.Set("Content-Type", "application/a2a+json")
			r.Header.Set("Content-Encoding", tc.encoding)
			coverage := &watchRequestCoverage{}
			blocked := watchRequestBody(t.Context(), r, watchRequestOptions{Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New(), Transport: TransportForward, Coverage: coverage})
			if blocked != tc.refuse {
				t.Fatalf("refusal=%v want=%v coverage=%+v", blocked, tc.refuse, coverage)
			}
			if blocked {
				if coverage.refusalReason == "" || coverage.refusalLayer == "" {
					t.Fatal("refusal lost classification")
				}
			} else {
				got, err := io.ReadAll(r.Body)
				if err != nil || string(got) != payload {
					t.Fatalf("replay changed: %q %v", got, err)
				}
			}
			if err := r.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if !closed {
				t.Fatal("replay leaked source")
			}
		})
	}
}

func TestWatchRequestReplayAccounting(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		opts := watchRequestOptions{Logger: audit.NewNop(), Metrics: metrics.New(), Transport: TransportForward}
		if deferred {
			opts.Coverage = &watchRequestCoverage{}
		}
		onRead := watchUninspectedRequestRead(opts, "fixture_parser", "bounded observation")
		if deferred {
			if onRead != nil || opts.Coverage.layer != "fixture_parser" || opts.Coverage.reason != "bounded observation" {
				t.Fatalf("coverage=%+v callback=%v", opts.Coverage, onRead != nil)
			}
			continue
		}
		accepted := 0
		closed := false
		source := &watchCoverageBody{Reader: strings.NewReader("original"), onClose: func() { closed = true }}
		replay := &watchRequestReplayBody{Reader: source, source: source, onRead: func(n int) { accepted += n; onRead(n) }}
		got, err := io.ReadAll(replay)
		if err != nil || string(got) != "original" || accepted != len(got) {
			t.Fatalf("replay=%q accepted=%d err=%v", got, accepted, err)
		}
		if err := replay.Close(); err != nil || !closed {
			t.Fatalf("source closed=%v err=%v", closed, err)
		}
	}
}
