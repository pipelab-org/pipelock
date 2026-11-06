// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"strings"
	"testing"
)

func TestTextEncodingSeedWholeTextViews(t *testing.T) {
	s := seedQuoteScanner(t)
	fullyEscaped := func(text string) string {
		var b strings.Builder
		for i := range len(text) {
			_, _ = fmt.Fprintf(&b, "=%02X", text[i])
		}
		return b.String()
	}
	for _, tc := range []struct{ name, encoding, carrier string }{
		{"decimal", encodingDecimal, decimalCharacterCodes(testSeedPhrase12, " ")},
		{"quoted printable", encodingQuotedPrintable, fullyEscaped(testSeedPhrase12)},
		{"quoted printable soft break", encodingQuotedPrintable, fullyEscaped(testSeedPhrase12[:7]) + "=\r\n" + fullyEscaped(testSeedPhrase12[7:])},
		{"octal", encodingOctal, prefixedCharacterCodes(testSeedPhrase12, "0o", 8)},
		{"binary", encodingBinary, prefixedCharacterCodes(testSeedPhrase12, "0b", 2)},
		{"invisible spaced", encodingDecimal, decimalCharacterCodes(strings.ReplaceAll(testSeedPhrase12, " ", "\u200b"), " ")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := s.ScanTextForDLP(t.Context(), tc.carrier)
			for _, m := range result.Matches {
				if m.PatternName == "BIP-39 Seed Phrase" && m.Encoded == tc.encoding {
					return
				}
			}
			t.Fatalf("encoded seed phrase not detected: %+v", result)
		})
	}
}
