// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"reflect"
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

func TestKnownValuePrefixRecoveryWorkBound(t *testing.T) {
	for _, tc := range []struct {
		name    string
		quantum int
		corrupt func(int) error
	}{
		{"base64", 4, func(offset int) error { return base64.CorruptInputError(offset) }},
		{"base32", 8, func(offset int) error { return base32.CorruptInputError(offset) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, size := range []int{64, maxDecodeTotalBytes} {
				value := strings.Repeat("A", size)
				calls := 0
				original := "retained content"
				result := recoverKnownValuePrefix(value, original, minKnownSecretSubstringLen, tc.quantum, tc.corrupt(size/2), func(string) ([]byte, error) { calls++; return nil, tc.corrupt(0) })
				if result != original || calls == 0 || calls > 2*tc.quantum-1 {
					t.Fatalf("result changed=%t decoder calls=%d", result != original, calls)
				}
			}
		})
	}
	original := "retained content"
	if result := recoverKnownValuePrefix(strings.Repeat("A", 64), original, minKnownSecretSubstringLen, 4, errors.ErrUnsupported, func(string) ([]byte, error) { t.Fatal("unsupported error must not trigger recovery"); return nil, nil }); result != original {
		t.Fatal("unsupported error changed retained bytes")
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
