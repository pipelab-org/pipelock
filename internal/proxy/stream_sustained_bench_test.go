// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// BenchmarkWSUpstreamCrossMessageSustainedNovel measures established streams
// whose full retained tail changes on every message. Leading spaces model LLM
// token deltas. Message-sized inputs contain 24 words; token-sized inputs one.
// Generation is timed equally on the baseline and candidate.
func BenchmarkWSUpstreamCrossMessageSustainedNovel(b *testing.B) {
	for _, size := range []struct {
		name  string
		words int
	}{
		{"TokenLeadingSpace", 1}, {"MessageLeadingSpace", 24},
	} {
		b.Run(size.name, func(b *testing.B) {
			cfg := config.Defaults()
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			log := audit.NewNop()
			relay := &wsRelay{cfg: cfg, scanner: sc, proxy: &Proxy{metrics: metrics.New(), logger: log}, scanText: true, targetURL: "https://api.vendor.example"}
			state := newUpstreamCrossMessage(config.DefaultWebSocketCrossMessageFieldLimit)
			generator := newNovelStreamText()
			for len(state.tail) < crossMsgOverlap {
				if state.enforce(b.Context(), relay, log, []byte(generator.next(size.words))) {
					b.Fatal("clean stream blocked during warmup")
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				msg := []byte(generator.next(size.words))
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
		})
	}
}

// novelStreamText emits deterministic ordinary words without replaying a fixed
// message or tail. Vocabulary may repeat, as in real token deltas, but the
// generator state continues across warmup, messages, and benchmark iterations.
// The step is a 64-bit linear congruential generator with Knuth's MMIX
// constants; the corpus only needs to be deterministic, not unpredictable.
type novelStreamText struct {
	state      uint64
	dictionary []string
}

func newNovelStreamText() *novelStreamText {
	const vocabulary = "the gardens rivers lights greens quietly mornings windows smaller clearly stories blues warmly roads fields clouds brighter leaves homes fresher stones rounded hills softly rains trees calmly lakes longer paths newer days"
	return &novelStreamText{state: 1, dictionary: strings.Fields(vocabulary)}
}

func (g *novelStreamText) nextIndex() uint64 {
	g.state = g.state*6364136223846793005 + 1442695040888963407
	return (g.state >> 33) % uint64(len(g.dictionary))
}

func (g *novelStreamText) next(words int) string {
	var out strings.Builder
	for range words {
		out.WriteByte(' ')
		out.WriteString(g.dictionary[g.nextIndex()])
	}
	return out.String()
}
