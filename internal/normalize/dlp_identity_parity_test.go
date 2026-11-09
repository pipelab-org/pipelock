// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

func TestForDLPPrintableASCIIReferenceParity(t *testing.T) {
	inputs := []string{"", "first body", "different body", " \"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~", "café", "e\u0301", "ＡＢＣ", "한글", "a\u200bb", "a\u00a0b", "\ufffd", strings.Repeat("plain text ", 1024)}
	for value := byte(0); ; value++ {
		text := string([]byte{value})
		inputs = append(inputs, text, "first"+text+"body", text+"other", "last"+text)
		if value == 255 {
			break
		}
	}
	changed, unchanged := 0, 0
	for i, input := range inputs {
		t.Run(fmt.Sprintf("input_%d", i), func(t *testing.T) {
			want := StripControlChars(input)
			want = StripExoticWhitespace(want)
			want = norm.NFKC.String(want)
			want = StripControlChars(want)
			want = ConfusableToASCII(want)
			want = StripCombiningMarks(want)
			if got := ForDLP(input); got != want {
				t.Fatalf("normalization differs for %q: got %q, want %q", input, got, want)
			}
			if want == input {
				unchanged++
			} else {
				changed++
			}
		})
	}
	if changed == 0 || unchanged == 0 {
		t.Fatalf("parity corpus lacks both paths: changed=%d unchanged=%d", changed, unchanged)
	}
}

func TestForDLPASCIIControlsReferenceParity(t *testing.T) {
	// Every ordered ASCII pair covers control deletion at either position,
	// including adjacent controls and all printable neighbours.
	for a := range 128 {
		for b := range 128 {
			input := "prefix" + string([]byte{byte(a), byte(b)}) + "suffix"
			if got, want := ForDLP(input), forDLPFull(input); got != want {
				t.Fatalf("ASCII pair %x: got %x, want %x", input, got, want)
			}
		}
	}
	for _, input := range []string{
		"\x00\x1f\x7f", "a\n", "\tword\r\n",
		"e\x00\u0301", "\x00\u1100\u1161", "\x7f\u0401",
		"a\n\xffb", "\t\u00a0b", "a\u0301\x00b",
	} {
		if got, want := ForDLP(input), forDLPFull(input); got != want {
			t.Fatalf("control fallback %x: got %x, want %x", input, got, want)
		}
	}
}
