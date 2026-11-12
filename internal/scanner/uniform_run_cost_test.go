// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestUniformRunDLPAllocationBound(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	text := strings.Repeat("x", 2<<20)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	result := s.ScanTextForDLP(context.Background(), text)
	runtime.ReadMemStats(&after)
	if !result.Clean {
		t.Fatalf("unexpected findings: %+v", result.Matches)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 640<<20 {
		t.Fatalf("uniform run allocated %d bytes; limit %d", allocated, 640<<20)
	}
}

func TestAssembledGrammarCachePreservesAdmission(t *testing.T) {
	shape, err := newAssembledShape(0, "abcd")
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{strings.Repeat("78", 100), strings.Repeat("78", 30) + "61626364" + strings.Repeat("78", 30), "61626364", "616263", "61626364"}
	var cache assembledGrammarCache
	found, missed := false, false
	for _, text := range inputs {
		for end := 2; end <= len(text); end += 2 {
			position := assembledPosition{codec: 0, phase: 0, symbols: end, end: end}
			var fresh assembledGrammarCache
			want := shape.grammarNear(text, position, &fresh)
			got := shape.grammarNear(text, position, &cache)
			if got != want {
				t.Fatalf("admission mismatch at end %d: got %v, want %v", end, got, want)
			}
			found = found || got
			missed = missed || !got
		}
	}
	if !found || !missed {
		t.Fatalf("test did not cover both admission results: found=%v missed=%v", found, missed)
	}
}

func TestAssembledOriginDenseAndSparse(t *testing.T) {
	for codec, c := range reassemblyCodecs {
		var cache assembledGrammarCache
		for _, text := range []string{strings.Repeat(string(c.alphabet[0]), 100), strings.Repeat(string(c.alphabet[0])+"!", 50), strings.Repeat("!"+string(c.alphabet[0]), 50)} {
			symbols := 0
			for i := range len(text) {
				if c.values[text[i]] < 0 {
					continue
				}
				symbols++
				for phase := range c.quantum {
					for _, n := range []int{0, 1, 4, 100} {
						position := assembledPosition{codec: codec, phase: phase, symbols: symbols, end: i + 1}
						count := max(0, (symbols-phase)*c.width/8)
						bit := phase*c.width + max(0, count-n)*8
						need := symbols - bit/c.width
						raw := i + 1
						for need > 0 && raw > 0 {
							raw--
							if c.values[text[raw]] >= 0 {
								need--
							}
						}
						want := reassemblyRef{raw: raw, skip: uint8(bit % c.width & 7)}
						if got := assembledOrigin(text, position, n); got != want {
							t.Fatalf("codec %d phase %d end %d n %d: got %+v want %+v", codec, phase, i+1, n, got, want)
						}
						if got := cachedAssembledOrigin(text, position, n, &cache); got != want {
							t.Fatalf("cached codec %d phase %d end %d n %d: got %+v want %+v", codec, phase, i+1, n, got, want)
						}
					}
				}
			}
		}
	}
}

func TestCachedAssembledOriginIrregularAndReverse(t *testing.T) {
	for codec, c := range reassemblyCodecs {
		var input strings.Builder
		for i := range 512 {
			if i%7 < 3 {
				input.WriteByte('!')
			} else {
				input.WriteByte(c.alphabet[(i*i+3*i)%len(c.alphabet)])
			}
		}
		text := input.String()
		positions := make([]assembledPosition, 0, len(text))
		symbols := 0
		for i := range len(text) {
			if c.values[text[i]] < 0 {
				continue
			}
			symbols++
			positions = append(positions, assembledPosition{codec: codec, symbols: symbols, end: i + 1})
		}
		var cache assembledGrammarCache
		for pass := range 2 {
			for i := range len(positions) {
				j := i
				if pass != 0 {
					j = len(positions) - 1 - i
				}
				for phase := range c.quantum {
					position := positions[j]
					position.phase = phase
					for _, n := range []int{0, 1, 7, 100} {
						want := assembledOrigin(text, position, n)
						if got := cachedAssembledOrigin(text, position, n, &cache); got != want {
							t.Fatalf("codec %d pass %d phase %d end %d n %d: got %+v want %+v", codec, pass, phase, position.end, n, got, want)
						}
					}
				}
			}
		}
	}
}
