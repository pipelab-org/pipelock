// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// These benchmarks fill the retained tail with the first event, then send 128
// novel events. Generator state continues across iterations; neither messages
// nor streams replay a fixed corpus. Both transports use the same word stream.
func BenchmarkGenericSSEInjectionSustainedNovel(b *testing.B) {
	benchmarkSustainedNovel(b, false)
}

func BenchmarkA2AStreamInjectionSustainedNovel(b *testing.B) {
	benchmarkSustainedNovel(b, true)
}

func benchmarkSustainedNovel(b *testing.B, a2a bool) {
	for _, size := range []struct {
		name  string
		words int
	}{
		{"TokenLeadingSpace", 1}, {"MessageLeadingSpace", 24},
	} {
		b.Run(size.name, func(b *testing.B) {
			cfg := config.Defaults()
			cfg.A2AScanning.Enabled = true
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			streamCfg := &config.GenericSSEScanning{Enabled: true, Action: config.ActionBlock}
			generator := newNovelStreamText()
			const events = 128
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				var seed strings.Builder
				for seed.Len() < rollingTailSize {
					seed.WriteString(generator.next(size.words))
				}
				var wire strings.Builder
				writeEvent := func(text string) {
					wire.WriteString("data: ")
					if a2a {
						// Ordinary words need no JSON escaping. Arrays are accepted A2A
						// event values, matching BenchmarkA2AStreamInjectionCleanRepeatedContent.
						wire.WriteString(`["`)
						wire.WriteString(text)
						wire.WriteString(`"]`)
					} else {
						wire.WriteString(text)
					}
					wire.WriteString("\n\n")
				}
				writeEvent(seed.String())
				for range events {
					writeEvent(generator.next(size.words))
				}
				var err error
				if a2a {
					err = ScanA2AStream(b.Context(), strings.NewReader(wire.String()), io.Discard, nil, sc, &cfg.A2AScanning)
				} else {
					err = ScanGenericSSEStream(b.Context(), strings.NewReader(wire.String()), io.Discard, nil, sc, streamCfg)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*(events+1)), "ns/event")
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
