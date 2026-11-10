// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

var wifTestVectors = []string{
	"5HueCGU8rMjx" + "EXxiPuD5BDku4MkFqe" + "Zyd4dZ1jvhTVqvbTLvyTJ",
	"KwdMAjGmer" + "Yanjeui5SHS7Jkmp" + "ZvVipYvB2LJGU1ZxJwYvP98617",
}

// generalWIFDecision is the general Base58Check decision the canonical fast
// path must reproduce.
func generalWIFDecision(s string) bool {
	payload, version, err := addressprotect.Base58CheckDecode(s)
	return err == nil && version == 0x80 && (len(payload) == 32 || (len(payload) == 33 && payload[32] == 0x01))
}

func TestValidateCanonicalWIFMatchesGeneralDecoder(t *testing.T) {
	rng := rand.New(rand.NewSource(1)) // #nosec G404 -- reproducible corpus.
	inputs := append([]string(nil), wifTestVectors...)
	for _, vector := range wifTestVectors {
		for i := 1; i < len(vector); i++ {
			for _, c := range []byte{'1', 'z', 'K', 'l', '0'} {
				inputs = append(inputs, vector[:i]+string(c)+vector[i+1:])
			}
		}
	}
	for i := 0; i < 20000; i++ {
		first := []byte{'5', 'K', 'L'}[rng.Intn(3)]
		width := wifUncompressedLen
		if first != '5' {
			width = wifCompressedLen
		}
		b := []byte{first}
		for len(b) < width {
			b = append(b, base58Alphabet[rng.Intn(len(base58Alphabet))])
		}
		inputs = append(inputs, string(b))
	}
	inputs = append(inputs, "5"+strings.Repeat("z", 50), "L"+strings.Repeat("z", 51), "K"+strings.Repeat("1", 51), "5"+strings.Repeat("1", 50))
	accepted := 0
	for _, input := range inputs {
		ok, canonical := validateCanonicalWIF(input)
		if !canonical {
			t.Fatalf("canonical-shaped input left the fast path: %q", input)
		}
		if want := generalWIFDecision(input); ok != want {
			t.Fatalf("fast WIF decision %v, general decoder %v for %q", ok, want, input)
		}
		if ok {
			accepted++
		}
	}
	if accepted < len(wifTestVectors) {
		t.Fatalf("accepted %d inputs, want at least the %d vectors", accepted, len(wifTestVectors))
	}
	for _, other := range []string{"", "K", "1" + wifTestVectors[0], wifTestVectors[1] + "1", strings.ToLower(wifTestVectors[1])} {
		if _, canonical := validateCanonicalWIF(other); canonical {
			t.Fatalf("non-canonical shape took the fast path: %q", other)
		}
		if validateWIF(other) != generalWIFDecision(other) {
			t.Fatalf("general path changed for %q", other)
		}
	}
}

// regexWIFSpan restarts the canonical regex one byte after each rejected start.
// It is the reference the single-pass enumerator must agree with.
func regexWIFSpan(text string, accept func(string) bool) (int, int, bool) {
	re := regexp.MustCompile("(?i)" + config.BitcoinWIFRegex)
	for offset := 0; offset < len(text); {
		loc := re.FindStringIndex(text[offset:])
		if loc == nil {
			break
		}
		start, end := offset+loc[0], offset+loc[1]
		if accept(text[start:end]) {
			return start, end, true
		}
		offset = start + 1
	}
	return 0, 0, false
}

func TestFirstWIFCandidateMatchesRegexRestart(t *testing.T) {
	rng := rand.New(rand.NewSource(2)) // #nosec G404 -- reproducible corpus.
	alphabet := base58Alphabet + "5KLKLkl0OIl-_ ."
	var texts []string
	for _, vector := range wifTestVectors {
		for _, prefix := range []string{"", "5", "K", "L", "k", "KL5", strings.Repeat("K", 53), strings.Repeat("5L", 40), "0", "-"} {
			for _, suffix := range []string{"", "K", "z", " ", strings.Repeat("L", 60)} {
				texts = append(texts, prefix+vector+suffix)
			}
		}
	}
	for i := 0; i < 3000; i++ {
		b := make([]byte, rng.Intn(300))
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		text := string(b)
		if rng.Intn(2) == 0 {
			at := rng.Intn(len(text) + 1)
			text = text[:at] + wifTestVectors[rng.Intn(len(wifTestVectors))] + text[at:]
		}
		texts = append(texts, text)
	}
	for _, text := range texts {
		wantStart, wantEnd, wantOK := regexWIFSpan(text, validateWIF)
		gotStart, gotEnd, gotOK := firstWIFCandidate(text, nil, func(start, end int) bool { return validateWIF(text[start:end]) })
		if gotOK != wantOK || gotStart != wantStart || gotEnd != wantEnd {
			t.Fatalf("enumerator %d:%d %v, regex restart %d:%d %v for %q", gotStart, gotEnd, gotOK, wantStart, wantEnd, wantOK, text)
		}
	}
}

// TestFirstWIFCandidateVisitsEachStartOnce bounds the enumeration itself: one
// acceptance call per eligible start, none for starts that cannot fit.
func TestFirstWIFCandidateVisitsEachStartOnce(t *testing.T) {
	text := strings.Repeat("K", 4096) + " " + strings.Repeat("5", 100) + "-" + strings.Repeat("L", 51)
	calls := 0
	if _, _, ok := firstWIFCandidate(text, nil, func(int, int) bool { calls++; return false }); ok {
		t.Fatal("rejecting acceptor produced a span")
	}
	if want := (4096 - wifCompressedLen + 1) + (100 - wifUncompressedLen + 1); calls != want {
		t.Fatalf("%d acceptance calls, want %d", calls, want)
	}
}

func BenchmarkWIFOverlapScan(b *testing.B) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	text := strings.Repeat("K", 64<<10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ScanTextForDLP(b.Context(), text)
	}
}
