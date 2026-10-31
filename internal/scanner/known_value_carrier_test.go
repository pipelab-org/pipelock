// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestKnownValueCarrierContent(t *testing.T) {
	value := strings.Join([]string{"fixture", "Q7m2", "X9z4", "R8v3", "N6p1"}, "-")
	sc := knownSecretEncodingScanner(t, []string{value})
	sc.entropyThreshold = 0 // Isolate DLP from the separate query-entropy policy.
	forms := []struct {
		name   string
		encode func(string) string
	}{
		{"hex", func(s string) string {
			return hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte("label:" + s))))
		}},
		{"base64", func(s string) string {
			return base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte("label:" + s))))
		}},
		{"base32", func(s string) string {
			return base32.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte("label:" + s))))
		}},
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			for _, suffix := range []string{"", "ZZ", "%41", "%ZZ", "f"} {
				t.Run("suffix="+suffix, func(t *testing.T) {
					for _, tc := range []struct {
						name, text string
						clean      bool
					}{
						{"configured", form.encode(value) + suffix, false},
						{"ordinary", form.encode("ordinary documentation") + suffix, true},
					} {
						t.Run(tc.name, func(t *testing.T) {
							for surface, result := range map[string]TextDLPResult{
								"text": sc.ScanTextForDLP(t.Context(), tc.text),
								"json": sc.ScanRequestBodyTextForDLP(t.Context(), `{"note":"`+tc.text+`"}`),
							} {
								if result.Clean != tc.clean || result.Incomplete {
									t.Errorf("%s clean=%t want=%t incomplete=%t", surface, result.Clean, tc.clean, result.Incomplete)
								}
							}
							for _, query := range []string{"q=" + url.QueryEscape(tc.text), "q=" + tc.text + "&x=1"} {
								result := sc.Scan(t.Context(), "https://api.vendor.example/?"+query)
								if result.Allowed != tc.clean || (!tc.clean && result.Scanner != ScannerDLP) {
									t.Errorf("URL allowed=%t want=%t scanner=%s", result.Allowed, tc.clean, result.Scanner)
								}
							}
						})
					}
				})
			}
		})
	}
}

func TestKnownValueDecodeModeIsolation(t *testing.T) {
	text := hex.EncodeToString([]byte("ordinary documentation")) + "ZZ"
	for _, knownFirst := range []bool{false, true} {
		var memo decodingMemo
		if knownFirst {
			memo.decodeKnownSecret(text, minKnownSecretSubstringLen)
		}
		ordinary := memo.decode(text, true)
		recovered := memo.decodeKnownSecret(text, minKnownSecretSubstringLen)
		if !reflect.DeepEqual(ordinary, decodeEncodingsFixpoint(text, true)) {
			t.Fatal("known-value recovery changed ordinary decoding")
		}
		found := false
		for _, view := range recovered {
			found = found || view.text == "ordinary documentation"
		}
		if !found {
			t.Fatal("decoded prefix missing")
		}
	}
	var noMemo *decodingMemo
	if !reflect.DeepEqual(noMemo.decodeKnownSecret(text, minKnownSecretSubstringLen), decodeEncodingsFixpointMode(text, true, minKnownSecretSubstringLen)) {
		t.Fatal("nil memo changed decoding")
	}
}

func TestKnownValueDecodeWorkBounds(t *testing.T) {
	if views := decodeEncodingsFixpointMode("%41", true, minKnownSecretSubstringLen); len(views) != 0 {
		t.Fatal("candidate shorter than the minimum match retained")
	}
	for _, text := range []string{
		strings.Repeat("41", maxDecodeTotalBytes/2) + "Z",
		strings.Repeat("41", maxDecodeTotalBytes/2-1) + "ZZ",
		strings.Repeat("%34%31", maxDecodeTotalBytes/6),
	} {
		views := decodeEncodingsFixpointMode(text, true, minKnownSecretSubstringLen)
		if len(text) <= maxDecodeTotalBytes && len(views) == 0 {
			t.Fatal("within-budget positive control produced no decoded views")
		}
		if len(views) > maxDecodeCandidates {
			t.Fatal("candidate budget exceeded")
		}
		total := 0
		for _, view := range views {
			total += len(view.text)
		}
		if total > maxDecodeTotalBytes {
			t.Fatalf("decoded byte budget exceeded: %d", total)
		}
		if len(text) > maxDecodeTotalBytes && len(views) != 0 {
			t.Fatal("oversized input decoded")
		}
	}
}

func TestKnownValueCarrierMinimumLength(t *testing.T) {
	value := strings.Join([]string{"Q7m2", "X9z4", "R8v3", "N6p1"}, "")
	sc := knownSecretEncodingScanner(t, []string{value})
	sc.entropyThreshold = 0
	for _, tc := range []struct {
		name, text string
		clean      bool
	}{
		{"configured", value, false},
		{"ordinary", "ordinary documentation", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := base64.StdEncoding.EncodeToString([]byte("user:" + tc.text))
			carrier := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(inner)) + "Z"
			if result := sc.ScanTextForDLP(t.Context(), carrier); result.Clean != tc.clean {
				t.Errorf("text clean=%t want=%t", result.Clean, tc.clean)
			}
			if result := sc.ScanRequestBodyTextForDLP(t.Context(), `{"note":"`+carrier+`"}`); result.Clean != tc.clean {
				t.Errorf("JSON clean=%t want=%t", result.Clean, tc.clean)
			}
			if result := sc.Scan(t.Context(), "https://api.vendor.example/?q="+carrier); result.Allowed != tc.clean || (!tc.clean && result.Scanner != ScannerDLP) {
				t.Errorf("URL allowed=%t want=%t scanner=%s", result.Allowed, tc.clean, result.Scanner)
			}
		})
	}
}

// recoveryEncoding pairs a decoder with its RFC 4648 group geometry.
type recoveryEncoding struct {
	name              string
	quantum, groupLen int
	decode            func(string) ([]byte, error)
}

var recoveryEncodings = []recoveryEncoding{
	{"base64", 4, 3, base64.StdEncoding.DecodeString},
	{"raw-base64", 4, 3, base64.RawStdEncoding.DecodeString},
	{"base64url", 4, 3, base64.URLEncoding.DecodeString},
	{"raw-base64url", 4, 3, base64.RawURLEncoding.DecodeString},
	{"base32", 8, 5, base32.StdEncoding.DecodeString},
	{"raw-base32", 8, 5, rawBase32Standard.DecodeString},
	{"base32hex", 8, 5, base32.HexEncoding.DecodeString},
	{"raw-base32hex", 8, 5, rawBase32Hex.DecodeString},
}

// referenceRecoverKnownValuePrefix decodes every candidate prefix in full.
// recoverKnownValuePrefix must return the same bytes without that rework.
func referenceRecoverKnownValuePrefix(value string, complete []byte, minimum, quantum int, decodeErr error, decode func(string) ([]byte, error)) string {
	decoded := ""
	if len(complete) >= minimum {
		decoded = string(complete)
	}
	var offset int
	var corrupt64 base64.CorruptInputError
	var corrupt32 base32.CorruptInputError
	switch {
	case decodeErr == nil:
		offset = len(value)
	case errors.As(decodeErr, &corrupt64):
		offset = int(corrupt64)
	case errors.As(decodeErr, &corrupt32):
		offset = int(corrupt32)
	default:
		return decoded
	}
	for end := min(len(value)-1, offset+quantum-1); end >= max(minimum, offset-quantum+1); end-- {
		prefix, err := decode(value[:end])
		if err == nil && len(prefix) >= minimum && len(prefix) > len(decoded) {
			decoded = string(prefix)
		}
	}
	return decoded
}

func TestKnownValuePrefixRecoveryMatchesFullPrefixDecode(t *testing.T) {
	// Symbols from every alphabet, both padding sentinels, and bytes no
	// alphabet accepts. Line breaks are excluded: callers strip them first.
	const symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_"
	noise := []byte{'=', '=', '!', '~', 0xff, '%'}
	r := rand.New(rand.NewPCG(1, 2))
	checked := 0
	for range 20000 {
		value := make([]byte, r.IntN(72))
		for i := range value {
			if r.IntN(16) == 0 {
				value[i] = noise[r.IntN(len(noise))]
			} else {
				value[i] = symbols[r.IntN(len(symbols))]
			}
		}
		minimum := []int{1, 4, minKnownSecretSubstringLen}[r.IntN(3)]
		for _, enc := range recoveryEncodings {
			complete, err := enc.decode(string(value))
			maxRead := 0
			got := recoverKnownValuePrefix(string(value), complete, minimum, enc.quantum, enc.groupLen, err, func(s string) ([]byte, error) {
				maxRead = max(maxRead, len(s))
				return enc.decode(s)
			})
			want := referenceRecoverKnownValuePrefix(string(value), complete, minimum, enc.quantum, err, enc.decode)
			if got != want {
				t.Fatalf("%s value=%q minimum=%d: got %x want %x", enc.name, value, minimum, got, want)
			}
			if maxRead > 3*enc.quantum {
				t.Fatalf("%s value=%q: decoder read %d bytes, want at most three groups", enc.name, value, maxRead)
			}
			if got != "" && len(got) > len(complete) {
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no input recovered bytes beyond the complete decode")
	}
}

func TestKnownValuePrefixRecoveryWorkBound(t *testing.T) {
	payload := make([]byte, 60<<10)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	for _, enc := range recoveryEncodings {
		if !strings.HasPrefix(enc.name, "raw-") {
			// A padded decoder cannot complete a group without padding;
			// the raw variant beside it recovers that group.
			continue
		}
		t.Run(enc.name, func(t *testing.T) {
			var encoded string
			switch {
			case strings.Contains(enc.name, "base64"):
				encoded = base64.RawStdEncoding.EncodeToString(payload)
			case strings.Contains(enc.name, "hex"):
				encoded = rawBase32Hex.EncodeToString(payload)
			default:
				encoded = rawBase32Standard.EncodeToString(payload)
			}
			if strings.Contains(enc.name, "url") {
				encoded = strings.NewReplacer("+", "-", "/", "_").Replace(encoded)
			}
			// Drop one symbol of the final group and append a byte no
			// alphabet accepts, so recovery must decode past the error group.
			value := encoded[:len(encoded)-1] + "!"
			complete, err := enc.decode(value)
			if err == nil {
				t.Fatal("carrier must fail to decode")
			}
			calls, read := 0, 0
			got := recoverKnownValuePrefix(value, complete, minKnownSecretSubstringLen, enc.quantum, enc.groupLen, err, func(s string) ([]byte, error) {
				calls++
				read += len(s)
				return enc.decode(s)
			})
			if !bytes.HasPrefix(payload, []byte(got)) || len(got) <= len(complete) {
				t.Fatalf("recovered %d bytes, complete decode %d", len(got), len(complete))
			}
			if calls == 0 || calls > 2*enc.quantum-1 || read > calls*3*enc.quantum {
				t.Fatalf("decoder calls=%d bytes read=%d for a %d-byte carrier", calls, read, len(value))
			}
		})
	}
	complete := []byte("retained content")
	if result := recoverKnownValuePrefix(strings.Repeat("A", 64), complete, minKnownSecretSubstringLen, 4, 3, errors.ErrUnsupported, func(string) ([]byte, error) { t.Fatal("unsupported error must not trigger recovery"); return nil, nil }); result != string(complete) {
		t.Fatal("unsupported error changed retained bytes")
	}
}

// allocatedBytes reports heap bytes allocated while f runs.
func allocatedBytes(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestKnownValuePrefixRecoveryAllocationBound(t *testing.T) {
	// A one-symbol-short carrier with a trailing invalid byte is the worst
	// case for prefix recovery: every decoder variant fails at the very end.
	payload := make([]byte, 3<<18)
	r := rand.New(rand.NewPCG(3, 4))
	for i := range payload {
		payload[i] = byte(r.Uint32())
	}
	b64 := base64.RawStdEncoding.EncodeToString(payload)
	b64 = b64[:len(b64)-1] + "!"
	b32 := rawBase32Standard.EncodeToString(payload[:5<<17])
	b32 = b32[:len(b32)-1] + "!"
	buffer := make([]byte, len(b64)) // Caller-owned scratch, as in decodeEncodingsMode.
	for _, tc := range []struct {
		name    string
		carrier string
		run     func(string) []string
	}{
		{"base64", b64, func(s string) []string {
			views := decodeBase64PaddingVariants(s, base64.StdEncoding, base64.RawStdEncoding, buffer, minKnownSecretSubstringLen)
			return views[:]
		}},
		{"base32", b32, func(s string) []string {
			var views []string
			for _, d := range appendBase32DecodesMode(nil, s, minKnownSecretSubstringLen) {
				views = append(views, d.text)
			}
			return views
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var views []string
			allocated := allocatedBytes(func() { views = tc.run(tc.carrier) })
			recovered := false
			for _, view := range views {
				recovered = recovered || (len(view) > len(payload)/2 && bytes.HasPrefix(payload, []byte(view)))
			}
			if !recovered {
				t.Fatal("worst-case carrier did not recover its decoded prefix")
			}
			// Each variant decodes the carrier once and keeps one string. Full
			// re-decoding of near-complete prefixes costs several times more.
			if limit := uint64(5 * len(tc.carrier)); allocated > limit {
				t.Fatalf("allocated %d bytes for a %d-byte carrier, limit %d", allocated, len(tc.carrier), limit)
			}
		})
	}
}

func TestKnownValuePrefixRecoveryIgnoresLineBreaks(t *testing.T) {
	payload := []byte("label:fixture-Q7m2-X9z4-R8v3-N6p1")
	r := rand.New(rand.NewPCG(5, 6))
	wrap := func(s string) string {
		var b strings.Builder
		for i := range len(s) {
			b.WriteByte(s[i])
			if r.IntN(3) == 0 {
				b.WriteString([]string{"\n", "\r\n", "\r"}[r.IntN(3)])
			}
		}
		return b.String()
	}
	b64 := base64.RawStdEncoding.EncodeToString(payload)
	b32 := rawBase32Standard.EncodeToString(payload)
	for _, carrier := range []string{b64[:len(b64)-1] + "!", b64[:len(b64)-2] + "%ZZ", b64 + "=!"} {
		buffer := make([]byte, 2*len(carrier))
		want := decodeBase64PaddingVariants(carrier, base64.StdEncoding, base64.RawStdEncoding, buffer, minKnownSecretSubstringLen)
		if want[1] == "" {
			t.Fatalf("%q: positive control recovered nothing", carrier)
		}
		for range 20 {
			if got := decodeBase64PaddingVariants(wrap(carrier), base64.StdEncoding, base64.RawStdEncoding, buffer, minKnownSecretSubstringLen); got != want {
				t.Fatalf("%q: line breaks changed base64 views", carrier)
			}
		}
	}
	for _, carrier := range []string{b32[:len(b32)-1] + "!", b32 + "1"} {
		want := appendBase32DecodesMode(nil, carrier, minKnownSecretSubstringLen)
		if len(want) == 0 {
			t.Fatalf("%q: positive control recovered nothing", carrier)
		}
		for range 20 {
			if got := appendBase32DecodesMode(nil, wrap(carrier), minKnownSecretSubstringLen); !reflect.DeepEqual(got, want) {
				t.Fatalf("%q: line breaks changed base32 views", carrier)
			}
		}
	}
}

func TestKnownValueCarrierLineBreaks(t *testing.T) {
	value := strings.Join([]string{"Q7m2", "X9z4", "R8v3", "N6p1"}, "")
	sc := knownSecretEncodingScanner(t, []string{value})
	for _, tc := range []struct {
		name, text string
		clean      bool
	}{
		{"configured", value, false},
		{"ordinary", "ordinary documentation", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", maxReassembledTokenLen) + "user:" + tc.text))
			encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(inner))
			var b strings.Builder
			for _, c := range encoded {
				b.WriteRune(c)
				b.WriteString("\r\n")
			}
			b.WriteString("%ZZ")
			result := sc.ScanTextForDLP(t.Context(), b.String())
			if result.Clean != tc.clean {
				t.Fatalf("line-break carrier clean=%t want=%t", result.Clean, tc.clean)
			}
		})
	}
}

func TestKnownValueViewsKeepCompleteDecodes(t *testing.T) {
	sc := knownSecretEncodingScanner(t, []string{"Q7m2X9z4R8v3N6p1"})
	// A long run that every byte decoder accepts yields large recovered
	// prefixes. They must not consume the budget of the complete-decode graph.
	var inner strings.Builder
	for _, c := range []byte(base64.StdEncoding.EncodeToString([]byte("user:ordinary documentation"))) {
		fmt.Fprintf(&inner, "%%%02X", c)
	}
	for _, text := range []string{
		strings.Repeat("a2b3c4d5e6f7", (9<<18)/12) + inner.String(),
		hex.EncodeToString([]byte("ordinary documentation")) + "ZZ",
	} {
		var memo decodingMemo
		views := sc.decodedKnownSecretViews(text, &memo)
		have := make(map[string]struct{}, len(views))
		for _, view := range views {
			have[view.text] = struct{}{}
		}
		for _, decoded := range decodeEncodingsFixpoint(text, true) {
			if _, ok := have[decoded.text]; !ok {
				t.Fatalf("complete %s decode missing from known-value views", decoded.encoding)
			}
		}
	}
}

func TestKnownValueCarrierBase32HexGlue(t *testing.T) {
	value := strings.Join([]string{"fixture", "Q7m2", "X9z4", "R8v3", "N6p1"}, "-")
	sc := knownSecretEncodingScanner(t, []string{value})
	for _, tc := range []struct {
		name, text string
		clean      bool
	}{
		{"configured", value, false},
		{"ordinary", "ordinary documentation", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := base32.HexEncoding.EncodeToString([]byte("label:" + tc.text))
			for _, carrier := range []string{"!" + encoded, encoded[:10] + "~" + encoded[10:]} {
				if result := sc.ScanTextForDLP(t.Context(), carrier); result.Clean != tc.clean {
					t.Errorf("text clean=%t want=%t", result.Clean, tc.clean)
				}
			}
		})
	}
}
