// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestAssembledAdmissionCacheEquivalence compares a warm admission cache with
// a cache that has never seen another position. A reused hit must not admit a
// window the fresh walk would reject, and it must not reject one the fresh
// walk would admit. The cache is deliberately shared across texts.
func TestAssembledAdmissionCacheEquivalence(t *testing.T) {
	synthetic := admissionSyntheticShapes(t)
	plan := reassemblyTestPlan(t)
	fixtures := dlpAgentTrafficFixtures(t)
	corpus := admissionRandomCorpus()
	var warm assembledGrammarCache
	for _, text := range corpus {
		exerciseAdmissionCache(t, synthetic, text, &warm)
	}
	for _, name := range []string{"AWS Access ID", "IBAN", "Bitcoin WIF Private Key", "Credit Card Number"} {
		plain := fixtures[name]
		if plain == "" {
			t.Fatalf("missing fixture %s", name)
		}
		for _, enc := range reassemblyEncodings(plain) {
			text := strings.Repeat("M", 180) + enc.text + strings.Repeat("Z", 90)
			exerciseAdmissionCache(t, plan.assembled.shapes, text, &warm)
			exerciseAdmissionCache(t, synthetic, text, &warm)
		}
	}
	// Walk the same texts backwards on the warm cache. A backward origin
	// request has to discard the forward cursor.
	for i := len(corpus) - 1; i >= 0; i-- {
		exerciseAdmissionCacheBackward(t, synthetic, corpus[i], &warm)
	}
}

func TestShortAdmissionWindowExtendsAtEOF(t *testing.T) {
	shape, err := newAssembledShape(0, "abcd")
	if err != nil {
		t.Fatal(err)
	}
	short := reassemblyEncodings("ab")[0].text
	long := reassemblyEncodings("abcd")[0].text
	var warm assembledGrammarCache
	exerciseAdmissionCache(t, []*assembledShape{shape}, short, &warm)
	var fresh assembledGrammarCache
	if got, want := admitAny(shape, long, &warm), admitAny(shape, long, &fresh); got != want || !want {
		t.Fatalf("extended text admission warm=%v fresh=%v", got, want)
	}
	// The long match must not stick to a later text that does not contain it.
	other := reassemblyEncodings("zzzz")[0].text
	var freshOther assembledGrammarCache
	if got, want := admitAny(shape, other, &warm), admitAny(shape, other, &freshOther); got != want || want {
		t.Fatalf("unrelated text admission warm=%v fresh=%v", got, want)
	}
}

func TestAnchoredAdmissionCacheEquivalence(t *testing.T) {
	var warm assembledGrammarCache
	for _, expr := range []string{`^abcd`, `abcd$`, `\babcd\b`, `(?i)^ab[cC]d$`} {
		shape, err := newAssembledShape(0, expr)
		if err != nil {
			t.Fatal(err)
		}
		for _, plain := range []string{"abcd", "zzabcd", "abcdzz", "zzabcdzz", "ab", "abcdabcd"} {
			for _, enc := range reassemblyEncodings(plain) {
				text := strings.Repeat("Q", enc.quantum) + enc.text + "!!" + enc.text
				exerciseAdmissionCache(t, []*assembledShape{shape}, text, &warm)
			}
		}
	}
}

func TestAssembledGrammarCacheBound(t *testing.T) {
	shape, err := newAssembledShape(0, "abcd")
	if err != nil {
		t.Fatal(err)
	}
	smallEntries, smallOrigins, smallRaw, smallDecoded := fillAdmissionCache(shape, 4_000)
	largeEntries, largeOrigins, largeRaw, largeDecoded := fillAdmissionCache(shape, 40_000)
	t.Logf("cache entries %d -> %d, origins %d -> %d, raw bytes %d -> %d, decoded bytes %d -> %d",
		smallEntries, largeEntries, smallOrigins, largeOrigins, smallRaw, largeRaw, smallDecoded, largeDecoded)
	if largeEntries > smallEntries || largeOrigins > smallOrigins {
		t.Fatalf("cache grew with input: entries %d -> %d origins %d -> %d", smallEntries, largeEntries, smallOrigins, largeOrigins)
	}
	if largeRaw > 1<<20 || largeDecoded > 1<<20 {
		t.Fatalf("cache retained raw=%d decoded=%d", largeRaw, largeDecoded)
	}
	// One cache fed a longer text must not grow past the per-key bound.
	var shared assembledGrammarCache
	fillOneAdmissionCache(shape, strings.Repeat("ab", 2_000), &shared)
	afterSmall := len(shared.entries) + len(shared.origins)
	fillOneAdmissionCache(shape, strings.Repeat("ab", 20_000), &shared)
	afterLarge := len(shared.entries) + len(shared.origins)
	if afterLarge > afterSmall {
		t.Fatalf("shared cache grew from %d slots to %d", afterSmall, afterLarge)
	}
}

func TestEncodedCredentialInUniformRun(t *testing.T) {
	aws := "AKIA" + strings.Repeat("V", 16)
	wif := wifTestVectors[0]
	for _, secret := range []struct{ name, plain string }{
		{"AWS Access ID", aws},
		{"Bitcoin WIF Private Key", wif},
	} {
		t.Run(secret.name, func(t *testing.T) {
			for _, enc := range reassemblyEncodings(secret.plain) {
				t.Run(enc.name, func(t *testing.T) {
					t.Parallel()
					cfg := config.Defaults()
					cfg.Internal = nil
					sc := MustNew(cfg)
					t.Cleanup(sc.Close)
					codec := reassemblyCodecByName(t, enc.name)
					alphabet := reassemblyCodecs[codec].alphabet[:1]
					sizes := []int{1 << 20, 2 << 20, 4 << 20}
					// The race detector multiplies the cost of these scans; one
					// size at one phase keeps the detection check in race runs.
					reduced := raceEnabled || testing.Short()
					if reduced {
						sizes = sizes[:1]
					}
					for _, size := range sizes {
						phases := enc.quantum
						if reduced || (secret.name != "AWS Access ID" && size != 1<<20) {
							phases = 1
						}
						for phase := range phases {
							body := uniformAlphabetCarrier(alphabet, enc.text, size, phase, enc.quantum)
							result := sc.ScanTextForDLP(context.Background(), body)
							if !slices.Contains(matchNames(result.Matches), secret.name) || uniformScanStopped(result) {
								t.Fatalf("size=%d phase=%d matches=%v incomplete=%v", size, phase, matchNames(result.Matches), uniformScanStopped(result))
							}
						}
					}
					sparse := strings.Repeat(alphabet+"!", 1<<20) + enc.text
					result := sc.ScanTextForDLP(context.Background(), sparse)
					if !slices.Contains(matchNames(result.Matches), secret.name) || uniformScanStopped(result) {
						t.Fatalf("sparse matches=%v incomplete=%v", matchNames(result.Matches), uniformScanStopped(result))
					}
				})
			}
		})
	}
}

func TestUniformRunCacheDoesNotStickAcrossScans(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	aws := "AKIA" + strings.Repeat("V", 16)
	other := "AKIA" + strings.Repeat("Q", 16)
	enc := reassemblyEncodings(aws)[1]
	otherEnc := reassemblyEncodings(other)[1]
	alphabet := reassemblyCodecs[1].alphabet[:1]
	first := uniformAlphabetCarrier(alphabet, enc.text, 1<<20, 1, enc.quantum)
	second := uniformAlphabetCarrier(alphabet, otherEnc.text, 1<<20, 3, otherEnc.quantum)
	clean := strings.Repeat(alphabet, 1<<20)
	for i, body := range []string{first, clean, second, first} {
		result := sc.ScanTextForDLP(context.Background(), body)
		found := slices.Contains(matchNames(result.Matches), "AWS Access ID")
		want := i != 1
		if found != want || uniformScanStopped(result) {
			t.Fatalf("scan %d found=%v want=%v incomplete=%v", i, found, want, uniformScanStopped(result))
		}
	}
}

func admissionSyntheticShapes(t *testing.T) []*assembledShape {
	t.Helper()
	var shapes []*assembledShape
	for _, expr := range []string{`abcd`, `^abcd`, `abcd$`, `\babcd\b`} {
		shape, err := newAssembledShape(0, expr)
		if err != nil {
			t.Fatal(err)
		}
		shapes = append(shapes, shape)
	}
	return shapes
}

func admissionRandomCorpus() []string {
	aws := "AKIA" + strings.Repeat("V", 16)
	out := []string{"", "!", "a", "A", strings.Repeat("a", 240), strings.Repeat("A!", 120), strings.Repeat("x", 500)}
	for _, enc := range reassemblyEncodings(aws) {
		out = append(out, enc.text, strings.Repeat("!", 30)+enc.text, strings.Repeat("A", 400)+enc.text+strings.Repeat("B", 80))
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/!-_ \n"
	for n := range 8 {
		rotated := alphabet[n:] + alphabet[:n]
		buf := strings.Repeat(rotated, 12)
		buf = buf[:60+n*40]
		payload := reassemblyEncodings(aws)[n%5].text
		at := (n*19 + 7) % (len(buf) + 1)
		out = append(out, buf[:at]+payload+buf[at:])
	}
	return out
}

func exerciseAdmissionCache(t *testing.T, shapes []*assembledShape, text string, warm *assembledGrammarCache) {
	t.Helper()
	exerciseAdmissionSample(t, shapes, text, warm, false)
}

func exerciseAdmissionCacheBackward(t *testing.T, shapes []*assembledShape, text string, warm *assembledGrammarCache) {
	t.Helper()
	exerciseAdmissionSample(t, shapes, text, warm, true)
}

func exerciseAdmissionSample(t *testing.T, shapes []*assembledShape, text string, warm *assembledGrammarCache, backward bool) {
	t.Helper()
	for codec := range reassemblyCodecs {
		positions := assembledSymbolPositions(text, codec)
		positions = sampleAdmissionPositions(positions, 48)
		if backward {
			slices.Reverse(positions)
		}
		quantum := reassemblyCodecs[codec].quantum
		for _, base := range positions {
			for phase := range quantum {
				position := base
				position.phase = phase
				for _, n := range []int{0, 1, 7, 64, position.symbols + 3} {
					want := assembledOrigin(text, position, n)
					if got := cachedAssembledOrigin(text, position, n, warm); got != want {
						t.Fatalf("origin codec %d phase %d end %d n %d backward %v: got %+v want %+v", codec, phase, position.end, n, backward, got, want)
					}
				}
				for _, shape := range shapes {
					var freshClass, freshGrammar assembledGrammarCache
					wantClass := shape.classRun(text, position, &freshClass)
					gotClass := shape.classRun(text, position, warm)
					wantGrammar := shape.grammarNear(text, position, &freshGrammar)
					gotGrammar := shape.grammarNear(text, position, warm)
					if gotClass != wantClass || gotGrammar != wantGrammar {
						t.Fatalf("codec %d phase %d end %d backward %v class %v/%v grammar %v/%v", codec, phase, position.end, backward, gotClass, wantClass, gotGrammar, wantGrammar)
					}
				}
			}
		}
	}
}

func admitAny(shape *assembledShape, text string, cache *assembledGrammarCache) bool {
	positions := assembledSymbolPositions(text, 0)
	for _, position := range positions {
		if shape.grammarNear(text, position, cache) && shape.classRun(text, position, cache) {
			return true
		}
	}
	return false
}

func assembledSymbolPositions(text string, codec int) []assembledPosition {
	c := &reassemblyCodecs[codec]
	positions := make([]assembledPosition, 0, len(text))
	symbols := 0
	for i := range len(text) {
		if c.values[text[i]] < 0 {
			continue
		}
		symbols++
		positions = append(positions, assembledPosition{codec: codec, symbols: symbols, end: i + 1})
	}
	return positions
}

func sampleAdmissionPositions(positions []assembledPosition, limit int) []assembledPosition {
	if len(positions) <= limit {
		return positions
	}
	out := make([]assembledPosition, 0, limit)
	out = append(out, positions[:8]...)
	out = append(out, positions[len(positions)-8:]...)
	stride := len(positions) / (limit - len(out))
	if stride < 1 {
		stride = 1
	}
	for i := 8; i < len(positions)-8 && len(out) < limit; i += stride {
		out = append(out, positions[i])
	}
	return out
}

func fillAdmissionCache(shape *assembledShape, n int) (entries, origins, rawBytes, decodedBytes int) {
	var cache assembledGrammarCache
	fillOneAdmissionCache(shape, strings.Repeat("ab", n), &cache)
	for _, entry := range cache.entries {
		rawBytes += len(entry.raw)
		decodedBytes += len(entry.previous)
	}
	return len(cache.entries), len(cache.origins), rawBytes, decodedBytes
}

func fillOneAdmissionCache(shape *assembledShape, text string, cache *assembledGrammarCache) {
	for _, position := range assembledSymbolPositions(text, 0) {
		for phase := range reassemblyCodecs[0].quantum {
			position.phase = phase
			shape.classRun(text, position, cache)
			shape.grammarNear(text, position, cache)
		}
	}
}

func uniformAlphabetCarrier(alphabet, payload string, size, phase, quantum int) string {
	if quantum < 1 {
		quantum = 1
	}
	pad := size - len(payload)
	if pad < quantum {
		pad = quantum
	}
	pad += (phase - pad%quantum + quantum) % quantum
	return strings.Repeat(alphabet, pad) + payload
}

func reassemblyCodecByName(t *testing.T, name string) int {
	t.Helper()
	for i, codec := range reassemblyCodecs {
		if codec.name == name {
			return i
		}
	}
	t.Fatalf("unknown codec %s", name)
	return 0
}

func uniformScanStopped(result TextDLPResult) bool {
	return result.Incomplete || HasInspectionLimit(result.Matches)
}
