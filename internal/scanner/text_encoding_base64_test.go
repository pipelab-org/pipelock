// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestMixedBase64ViewsPreserveFullTransform(t *testing.T) {
	inputs := []string{"", "!", "+/--__", "+/--__!", "+/--__=", "+/--__\r\n", "!+/--__", strings.Repeat("a ", maxReassembledTokenLen) + "+_-"}
	for _, n := range []int{maxReassembledTokenLen - 1, maxReassembledTokenLen, maxReassembledTokenLen + 1} {
		inputs = append(inputs, strings.Repeat("a", n)+"+_-!", strings.Repeat("a", n)+"+_-")
	}
	for value := byte(0); ; value++ {
		for _, prefix := range []string{"+/--__", "YWJj+/--__", strings.Repeat("a", 32) + "+_-"} {
			inputs = append(inputs, prefix+string([]byte{value}), string([]byte{value})+prefix)
		}
		if value == 255 {
			break
		}
	}
	for i, input := range inputs {
		full := mixedBase64Symbols.Replace(input)
		if got, want := normalizeMixedBase64Token(input), normalizeEncodedToken(full, encodedTokenBase64Std); got != want {
			t.Fatalf("normalization case %d differs", i)
		}
		if !mixedBase64AlphabetPossible(input) {
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
				if _, err := encoding.DecodeString(full); err == nil {
					t.Fatalf("case %d rejected a complete decode", i)
				}
			}
		}
		for _, minimum := range []int{0, minKnownSecretSubstringLen} {
			scratch := make([]byte, base64.RawStdEncoding.DecodedLen(len(input)))
			var want []decodedResult
			if mixed := canonicalMixedBase64(input); mixed != input {
				for _, value := range decodeBase64PaddingVariants(mixed, base64.StdEncoding, base64.RawStdEncoding, scratch, minimum) {
					want = appendBase64View(want, value)
				}
				if normalized := normalizeEncodedToken(mixed, encodedTokenBase64Std); normalized != "" {
					for _, value := range decodeBase64PaddingVariants(normalized, base64.StdEncoding, base64.RawStdEncoding, scratch, minimum) {
						want = appendBase64View(want, value)
					}
				}
			}
			if got := appendMixedBase64Views(nil, input, scratch, minimum); !reflect.DeepEqual(got, want) {
				t.Fatalf("ordered views differ in case %d, minimum %d", i, minimum)
			}
		}
	}
}

func TestMixedBase64OversizedRejectionDoesNotCopy(t *testing.T) {
	input := "!" + strings.Repeat("ordinary prose +_- ", 8192)
	scratch := make([]byte, base64DecodeScratchLen(input))
	if allocations := testing.AllocsPerRun(1, func() {
		if views := appendMixedBase64Views(nil, input, scratch, 0); len(views) != 0 {
			t.Fatal("oversized invalid carrier produced a view")
		}
	}); allocations != 0 {
		t.Fatalf("rejected carrier allocated %.0f objects", allocations)
	}
}

func TestTextEncodingMixedBase64Separators(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	key := "xoxb-" + "1234567890abcdef"
	mixed := mixedBase64Fixture(t, key)
	for _, sep := range []string{":", "!", ";"} {
		t.Run(sep, func(t *testing.T) {
			var groups []string
			for i := 0; i < len(mixed); i += 4 {
				groups = append(groups, mixed[i:min(i+4, len(mixed))])
			}
			carrier := strings.Join(groups, sep)
			result := s.ScanTextForDLP(t.Context(), carrier)
			for _, m := range result.Matches {
				if m.PatternName == "Slack Token" {
					return
				}
			}
			t.Fatalf("mixed base64 credential not detected: %+v", result)
		})
	}
}

func TestTextEncodingMixedBase64ReassemblyLimit(t *testing.T) {
	for _, size := range []int{maxReassembledTokenLen, maxReassembledTokenLen + 4} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			plaintext := "???~~~" + strings.Repeat("a", size/4*3-6)
			mixed := strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(plaintext)), "/", "_")
			var groups []string
			for i := 0; i < len(mixed); i += 4 {
				groups = append(groups, mixed[i:min(i+4, len(mixed))])
			}
			found := false
			for _, view := range decodeEncodings(strings.Join(groups, ":")) {
				if view.encoding == encodingBase64 && view.text == plaintext {
					found = true
				}
			}
			if want := size <= maxReassembledTokenLen; found != want {
				t.Fatalf("decoded=%v want=%v at reassembly size %d", found, want, size)
			}
		})
	}
}
