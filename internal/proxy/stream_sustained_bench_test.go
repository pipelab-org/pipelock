// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// BenchmarkWSUpstreamCrossMessageSustainedClean measures an established stream:
// the retained tail is full before timing and stays full for every message.
func BenchmarkWSUpstreamCrossMessageSustainedClean(b *testing.B) {
	cfg := config.Defaults()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	log := audit.NewNop()
	relay := &wsRelay{cfg: cfg, scanner: sc, proxy: &Proxy{metrics: metrics.New(), logger: log}, scanText: true, targetURL: "https://api.vendor.example"}
	msg := bytes.Repeat([]byte("The report is ready for review. "), 4)
	state := newUpstreamCrossMessage(config.DefaultWebSocketCrossMessageFieldLimit)
	for len(state.tail) < crossMsgOverlap {
		if state.enforce(b.Context(), relay, log, msg) {
			b.Fatal("clean stream blocked during warmup")
		}
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for b.Loop() {
		if _, blocked := relay.enforceUpstreamTextPayload(b.Context(), log, msg, true); blocked {
			b.Fatal("clean message blocked")
		}
		if state.enforce(b.Context(), relay, log, msg) {
			b.Fatal("clean stream blocked")
		}
		if len(state.tail) != crossMsgOverlap {
			b.Fatal("retained tail is not full")
		}
	}
}
