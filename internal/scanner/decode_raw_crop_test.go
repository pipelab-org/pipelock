// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// The bounds under test hand a raw decoder only the bytes it can consume. These
// tests compare each bounded decode with the decode of the whole input: same
// bytes and the same error, including its offset. Every reference below is the
// behaviour before the bound existed.

func sameDecode(t *testing.T, label string, got, want []byte, gotErr, wantErr error) {
	t.Helper()
	if string(got) != string(want) {
		t.Fatalf("%s: decoded bytes differ: got %q want %q", label, got, want)
	}
	if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
		t.Fatalf("%s: error differs: got %v want %v", label, gotErr, wantErr)
	}
}

func TestHexDecodeEndKeepsDecodeResult(t *testing.T) {
	for _, c := range rawCropCorpus() {
		want, wantErr := hex.DecodeString(c.text)
		got, gotErr := hex.DecodeString(c.text[:hexDecodeEnd(c.text)])
		sameDecode(t, "hex "+c.name, got, want, gotErr, wantErr)
	}
	// The invalid byte is kept: dropping it would turn an invalid byte into a
	// length error, or a pair into an odd tail.
	for _, text := range []string{"zz", "az", "0g", "00zz", "000g", "abc", "abcz"} {
		want, wantErr := hex.DecodeString(text)
		got, gotErr := hex.DecodeString(text[:hexDecodeEnd(text)])
		sameDecode(t, "hex "+text, got, want, gotErr, wantErr)
	}
	if got := hexDecodeEnd("0a0b"); got != 4 {
		t.Fatalf("valid hex is bounded at %d", got)
	}
}

func TestBase32DecodeEndKeepsDecodeResult(t *testing.T) {
	encodings := []struct {
		name string
		enc  *base32.Encoding
		hex  bool
	}{
		{"std", base32.StdEncoding, false},
		{"std-raw", rawBase32Standard, false},
		{"hex", base32.HexEncoding, true},
		{"hex-raw", rawBase32Hex, true},
	}
	var inputs []string
	for _, c := range rawCropCorpus() {
		inputs = append(inputs, c.text, normalize.ASCIIUpper(c.text), strings.ReplaceAll(strings.ReplaceAll(normalize.ASCIIUpper(c.text), "\r", ""), "\n", ""))
	}
	for _, e := range encodings {
		for _, text := range inputs {
			want, wantErr := e.enc.DecodeString(text)
			got, gotErr := e.enc.DecodeString(text[:base32DecodeEnd(text, e.hex, false)])
			sameDecode(t, "base32 "+e.name, got, want, gotErr, wantErr)
		}
	}
}

// Padding looks at what follows it, and the raw decoder's sentinel is 0xff, so
// neither may be cut away from its tail.
func TestBase32DecodeEndKeepsPaddingTail(t *testing.T) {
	for _, text := range []string{
		"AB=" + strings.Repeat("A", 40), "ABCDEFG=" + strings.Repeat("=", 3) + "!",
		"ABC\xff" + strings.Repeat("A", 40) + "!", "ABCDE=\r\n=!",
	} {
		if got := base32DecodeEnd(text, false, false); got != len(text) {
			t.Fatalf("%q: padding before an invalid byte was cropped to %d of %d", text, got, len(text))
		}
	}
	if got := base32DecodeEnd("ABCD!"+strings.Repeat("A", 100), false, false); got != 5 {
		t.Fatalf("plain invalid byte not the bound: %d", got)
	}
	if got := base32DecodeEnd("AB\r\nCD!E", false, false); got != 7 {
		t.Fatalf("line breaks are not bytes of the bound: %d", got)
	}
}

func TestFoldedBase32DecodeInputMatchesFullFold(t *testing.T) {
	var inputs []string
	for _, c := range rawCropCorpus() {
		inputs = append(inputs, c.text)
	}
	// Invalid UTF-8 changes the length of the fold; every byte of 0x80 or more
	// is invalid base32 wherever the fold moves it.
	inputs = append(inputs, "abc\xff\xfedef"+strings.Repeat("a", 50), "ab\xc3", "\xe2\x82", "abc\xe2\x82\xacdef", "ab\x80cd=")
	for _, e := range []struct {
		hex        bool
		padded, rw *base32.Encoding
	}{{false, base32.StdEncoding, rawBase32Standard}, {true, base32.HexEncoding, rawBase32Hex}} {
		for _, text := range inputs {
			folded := normalize.ASCIIUpper(text)
			bounded := foldedBase32DecodeInput(text, e.hex)
			for _, enc := range []*base32.Encoding{e.padded, e.rw} {
				want, wantErr := enc.DecodeString(folded)
				got, gotErr := enc.DecodeString(bounded)
				sameDecode(t, "folded base32", got, want, gotErr, wantErr)
			}
		}
	}
}

func referenceNormalizedFold(s string, kind encodedTokenKind) string {
	folded := normalize.ASCIIUpper(s)
	if normalized := normalizeEncodedToken(folded, kind); normalized != folded {
		return normalized
	}
	return ""
}

func TestNormalizeFoldedTokenMatchesFullFold(t *testing.T) {
	inputs := []string{"abc\xffdef-ghij", "ab\xc3\xa9cd2345", strings.Repeat("a-", maxReassembledTokenLen), strings.Repeat("a-", maxReassembledTokenLen/2)}
	for _, c := range rawCropCorpus() {
		inputs = append(inputs, c.text)
	}
	for _, kind := range []encodedTokenKind{encodedTokenBase32, encodedTokenBase32Hex} {
		for _, text := range inputs {
			if got, want := normalizeFoldedToken(text, kind), referenceNormalizedFold(text, kind); got != want {
				t.Fatalf("kind %d: normalizeFoldedToken(%.40q) = %.40q, want %.40q", kind, text, got, want)
			}
		}
	}
}

// referenceKnownBase32Views is the known-prefix base32 pass as it was written
// before any bound: the whole input folded once and every decoder given it.
func referenceKnownBase32Views(out []decodedResult, s string, minPrefix int) []decodedResult {
	folded := normalize.ASCIIUpper(s)
	out = referenceBase32AlphabetDecodes(out, folded, minPrefix, base32Alphabets)
	if normalized := normalizeEncodedToken(folded, encodedTokenBase32); normalized != "" && normalized != folded {
		out = referenceBase32AlphabetDecodes(out, normalized, minPrefix, base32Alphabets)
	}
	if normalized := normalizeEncodedToken(folded, encodedTokenBase32Hex); normalized != "" && normalized != folded {
		out = referenceBase32AlphabetDecodes(out, normalized, minPrefix, base32HexAlphabet)
	}
	return out
}

// referenceBase32AlphabetDecodes is appendBase32AlphabetDecodes with each
// decoder reading all of value.
func referenceBase32AlphabetDecodes(out []decodedResult, value string, minPrefix int, alphabets []base32Alphabet) []decodedResult {
	if minPrefix > 0 {
		value = strings.ReplaceAll(strings.ReplaceAll(value, "\r", ""), "\n", "")
	}
	for _, alphabet := range alphabets {
		prefix := value
		if minPrefix > 0 {
			prefix = value[:min(len(value), alphabet.raw.EncodedLen(minPrefix))]
		}
		if !base32PrefixPossible(prefix, alphabet.hex) {
			continue
		}
		paddedText := ""
		decoded, err := alphabet.padded.DecodeString(value)
		paddedComplete := err == nil
		switch {
		case err == nil:
			if len(decoded) >= max(minPrefix, 1) {
				paddedText = string(decoded)
			}
		case minPrefix > 0:
			paddedText = recoverKnownValuePrefix(value, decoded, minPrefix, 8, 5, err, alphabet.padded.DecodeString)
		}
		if paddedText != "" {
			out = append(out, decodedResult{text: paddedText, encoding: encodingBase32})
		}
		if paddedComplete && paddedText != "" && strings.IndexByte(value, '=') < 0 && strings.IndexByte(value, 0xff) < 0 {
			out = append(out, decodedResult{text: paddedText, encoding: encodingBase32})
			continue
		}
		rawText := ""
		decoded, err = alphabet.raw.DecodeString(value)
		switch {
		case minPrefix > 0 && (err != nil || len(decoded) < alphabet.raw.DecodedLen(len(value))):
			rawText = recoverKnownValuePrefix(value, decoded, minPrefix, 8, 5, err, alphabet.raw.DecodeString)
		case err == nil && len(decoded) >= max(minPrefix, 1):
			rawText = string(decoded)
		}
		if rawText != "" {
			out = append(out, decodedResult{text: rawText, encoding: encodingBase32})
		}
	}
	return out
}

func sameViews(t *testing.T, label string, got, want []decodedResult) {
	t.Helper()
	if !slices.EqualFunc(got, want, func(a, b decodedResult) bool { return a.text == b.text && a.encoding == b.encoding }) {
		t.Fatalf("%s: views differ: got %d, want %d", label, len(got), len(want))
	}
}

func TestKnownBase32ViewsMatchUnboundedDecoders(t *testing.T) {
	for _, c := range rawCropCorpus() {
		for _, minPrefix := range rawCropMinPrefixes[1:] {
			sameViews(t, c.name, appendKnownBase32Views(nil, c.text, minPrefix), referenceKnownBase32Views(nil, c.text, minPrefix))
		}
	}
}

// referenceMixedBase64Views is appendMixedBase64Views with the alphabet map
// applied to the whole text before any bound.
func referenceMixedBase64Views(out []decodedResult, text string, scratch []byte, minimum int) []decodedResult {
	if !strings.ContainsAny(text, "+/") || !strings.ContainsAny(text, "-_") {
		return out
	}
	if minimum > 0 || mixedBase64AlphabetPossible(text) {
		for _, decoded := range decodeBase64PaddingVariants(canonicalMixedBase64(text), base64.StdEncoding, base64.RawStdEncoding, scratch, minimum) {
			out = appendBase64View(out, decoded)
		}
	}
	if normalized := normalizeMixedBase64Token(text); normalized != "" {
		for _, decoded := range decodeBase64PaddingVariants(normalized, base64.StdEncoding, base64.RawStdEncoding, scratch, minimum) {
			out = appendBase64View(out, decoded)
		}
	}
	return out
}

func TestMixedBase64ViewsMatchUnboundedDecoders(t *testing.T) {
	cases := rawCropCorpus()
	// The prefix holds one symbol family and the other follows far later: the
	// whole text, not the prefix, decides that '-' and '_' are canonicalized.
	late := strings.Repeat("A", 60) + "-_" + strings.Repeat("B", 60) + "+/" + strings.Repeat("C", 30)
	cases = append(cases,
		rawCropCase{"late-family", late},
		rawCropCase{"late-family-bad", late + "!" + late},
		rawCropCase{"prefix-urlsafe-only", "-_-_-_-_" + strings.Repeat("Q", 40) + "!" + strings.Repeat("+/", 20)},
		rawCropCase{"bad-before-family", "ab!" + strings.Repeat("A", 40) + "-_" + "+/"},
		rawCropCase{"pad-before-bad", strings.Repeat("A", 38) + "==" + "!" + "-_+/"},
		rawCropCase{"newline-in-prefix", strings.Repeat("A", 30) + "\r\n" + strings.Repeat("-", 8) + "!" + "+/"},
	)
	for _, c := range cases {
		scratch := make([]byte, base64.RawStdEncoding.DecodedLen(len(c.text)))
		for _, minimum := range rawCropMinPrefixes {
			sameViews(t, c.name, appendMixedBase64Views(nil, c.text, scratch, minimum), referenceMixedBase64Views(nil, c.text, scratch, minimum))
		}
	}
	// Mapping a prefix is the prefix of mapping the text.
	if got, want := mixedBase64Symbols.Replace(late[:90]), mixedBase64Symbols.Replace(late)[:90]; got != want {
		t.Fatal("bytewise alphabet map is not prefix-stable")
	}
	for _, tc := range []struct {
		text string
		want int
	}{
		{"AAAA!BBBB", 5}, {"AA\r\nAA-_!x", 9}, {"AAAA=!", 6}, {"AAAA", 4}, {"A-_+/ A", 6},
	} {
		if got := mixedBase64DecodeEnd(tc.text); got != tc.want {
			t.Fatalf("mixedBase64DecodeEnd(%q) = %d, want %d", tc.text, got, tc.want)
		}
	}
}

// A decode that fails on its first bytes must not allocate in proportion to
// the text behind them. This is the mechanism: without the bounds, hex sizes
// its output, base32 copies its input, the known-prefix fold copies the whole
// text, and the alphabet map copies it again.
func TestRawCodecAttemptsDoNotAllocateForRejectedSuffix(t *testing.T) {
	const size = 1 << 20
	suffix := strings.Repeat("zQ+/-_ab", size/8)
	for _, tc := range []struct {
		name, text string
	}{
		{"json", `{"k":"` + suffix},
		{"hex-then-junk", "abcdefabcdefabcdefabcdefabcdefabcdef!" + suffix},
		{"base32-then-junk", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP!" + suffix},
		{"mixed-then-junk", "AAAA-_AAAA+/AAAAAAAAAAAAAAAAAAAAAAAA!" + suffix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			best := ^uint64(0)
			for range 3 {
				var before, after runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&before)
				_ = decodeEncodingsModeInto(nil, tc.text, minKnownSecretSubstringLen)
				runtime.ReadMemStats(&after)
				best = min(best, after.TotalAlloc-before.TotalAlloc)
			}
			if best > size/16 {
				t.Fatalf("a %d byte text with a rejected start allocated %d bytes", len(tc.text), best)
			}
		})
	}
}

func TestRawCodecBoundsKeepValidCarriers(t *testing.T) {
	secret := []byte(strings.Repeat("credential-shaped-value ", 40))
	for _, tc := range []struct {
		name, text string
		want       string
	}{
		{"hex", hex.EncodeToString(secret), string(secret)},
		{"base32", base32.StdEncoding.EncodeToString(secret), string(secret)},
		{"base32-hex", strings.ToLower(base32.HexEncoding.EncodeToString(secret)), string(secret)},
		{"base64", base64.StdEncoding.EncodeToString(secret), string(secret)},
	} {
		for _, minimum := range []int{0, minKnownSecretSubstringLen} {
			found := false
			for _, view := range decodeEncodingsModeInto(nil, tc.text, minimum) {
				found = found || view.text == tc.want
			}
			if !found {
				t.Fatalf("%s: valid carrier lost at minimum %d", tc.name, minimum)
			}
		}
	}
	// A long carrier cut by one invalid byte still yields its prefix.
	cut := hex.EncodeToString(secret) + "!" + strings.Repeat("0", 64)
	var recovered bool
	for _, view := range decodeEncodingsModeInto(nil, cut, minKnownSecretSubstringLen) {
		recovered = recovered || (view.encoding == encodingHex && view.text == string(secret))
	}
	if !recovered {
		t.Fatal("hex prefix before an invalid byte was not recovered")
	}
}
