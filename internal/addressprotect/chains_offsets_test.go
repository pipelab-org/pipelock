// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestBTCDetectOriginalOffsets(t *testing.T) {
	t.Parallel()
	const address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	for _, prefix := range []string{"plain ", "\u023a ", "\u212a ", "\u0130 "} {
		for _, addr := range []string{address, strings.ToUpper(address)} {
			t.Run(prefix+addr, func(t *testing.T) {
				matches := (btcValidator{}).Detect(prefix + addr)
				if len(matches) != 1 {
					t.Fatalf("matches = %v", matches)
				}
				if matches[0].offset != len(prefix) || matches[0].text != addr {
					t.Fatalf("wrong original span: %+v", matches[0])
				}
			})
		}
	}
}

func TestBNBDetectCaseMappingOffsets(t *testing.T) {
	const address = "bnb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq38lnxn"
	var runes []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		for _, mapped := range []rune{unicode.ToLower(r), unicode.ToUpper(r), unicode.ToTitle(r), unicode.SimpleFold(r)} {
			if utf8.RuneLen(mapped) != utf8.RuneLen(r) {
				runes = append(runes, r)
				break
			}
		}
	}
	if len(runes) == 0 {
		t.Fatal("Unicode case-mapping corpus is empty")
	}
	var prefixes []string
	for _, r := range runes {
		prefixes = append(prefixes, string(r)+" ")
	}
	prefixes = append(prefixes, "plain ", "\xff\xfe ", "\xe2\x82 ")
	for _, addr := range []string{address, strings.ToUpper(address)} {
		for _, prefix := range prefixes {
			matches := (bnbValidator{}).Detect(prefix + addr)
			if len(matches) != 1 || matches[0].offset != len(prefix) || matches[0].text != addr {
				t.Fatalf("prefix %q: wrong original span: %+v", prefix, matches)
			}
			if !(bnbValidator{}).Validate(matches[0].text) {
				t.Fatal("detected address did not validate")
			}
		}
	}
}
