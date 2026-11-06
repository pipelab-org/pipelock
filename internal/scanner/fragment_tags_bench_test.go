// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func benchmarkTagText(text string) string {
	var out strings.Builder
	for _, r := range text {
		out.WriteRune(0xE0000 + r)
	}
	return out.String()
}

func BenchmarkFragmentTagContinuity(b *testing.B) {
	for _, count := range []int{0, 1, 4, 8, 12} {
		for _, worst := range []bool{false, true} {
			b.Run(fmt.Sprintf("tags=%d/worst=%v", count, worst), func(b *testing.B) {
				sc := MustNew(benchConfig())
				b.Cleanup(sc.Close)
				n := max(count, minFragmentsForMatch)
				fragments := make([]fragment, n)
				// For twelve choices the retained candidate bytes approach the existing
				// maxDecodeTotalBytes ceiling without crossing it.
				size := 40
				if worst {
					size = (maxDecodeTotalBytes/maxDecodeCandidates - 1) / n
				}
				for i := range fragments {
					text := " ordinary prose "
					if i < count {
						text += benchmarkTagText("x")
					}
					if size > len(text) {
						text += strings.Repeat(" ", size-len(text))
					}
					fragments[i] = fragment{data: []byte(text)}
				}
				passes := benchmarkFragmentTagPasses(b, fragments)
				_ = scanOneFragmentContinuity(context.Background(), sc, fragments)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					_ = scanOneFragmentContinuity(context.Background(), sc, fragments)
				}
				b.ReportMetric(float64(passes), "dlp-passes/op")
			})
		}
	}
}

// A warning-only marker emits once per joined scan without invoking the
// contributor attribution rescans. Probe outside the measured benchmark.
func benchmarkFragmentTagPasses(tb testing.TB, fragments []fragment) int {
	tb.Helper()
	cfg := benchConfig()
	const marker = "fragment scan marker"
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name: marker, Regex: "ordinary prose", Action: config.ActionWarn, Severity: config.SeverityLow,
	})
	sc := MustNew(cfg)
	defer sc.Close()
	passes := 0
	sc.SetDLPWarnHook(func(_ context.Context, name, _ string) {
		if name == marker {
			passes++
		}
	})
	if matches := scanOneFragmentContinuity(context.Background(), sc, fragments); len(matches) != 0 {
		tb.Fatalf("benign fragment probe produced findings: %+v", matches)
	}
	return passes
}

func TestUnicodeTagsFragmentLinearViews(t *testing.T) {
	for _, count := range []int{0, 1, 4, 8, 12, 14} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			fragments := make([]fragment, max(count, minFragmentsForMatch))
			for i := range fragments {
				text := " ordinary prose "
				if i < count {
					text += benchmarkTagText("x")
				}
				fragments[i] = fragment{data: []byte(text)}
			}
			want := 1
			if count != 0 {
				want = 2 // The stripped and decoded whole-stream interpretations.
			}
			if passes := benchmarkFragmentTagPasses(t, fragments); passes != want {
				t.Fatalf("DLP passes = %d, want %d", passes, want)
			}
		})
	}
}
