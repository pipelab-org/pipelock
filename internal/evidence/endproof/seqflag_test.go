// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package endproof

import (
	"math"
	"testing"
)

func TestParseSeqAcceptsOnlyDecimalDigits(t *testing.T) {
	for text, want := range map[string]uint64{
		"0":                    0,
		"2":                    2,
		"02":                   2,
		"010":                  10,
		"18446744073709551615": math.MaxUint64,
	} {
		got, err := ParseSeq(text)
		if err != nil || got != want {
			t.Fatalf("ParseSeq(%q) = %d, %v; want %d", text, got, err, want)
		}
	}
	for _, text := range []string{"", "+2", "-1", "0x2", "0o7", "0b1", " 2", "2 ", "1_0", "18446744073709551616"} {
		if got, err := ParseSeq(text); err == nil {
			t.Fatalf("ParseSeq(%q) = %d, want error", text, got)
		}
	}
}

func TestSeqFlagSetsOnlyParsedValue(t *testing.T) {
	var seq uint64 = 7
	flag := SeqFlag{Seq: &seq}
	if err := flag.Set("0x2"); err == nil || seq != 7 {
		t.Fatalf("Set(0x2) err=%v seq=%d, want error and unchanged value", err, seq)
	}
	if err := flag.Set("010"); err != nil || seq != 10 || flag.String() != "10" {
		t.Fatalf("Set(010) err=%v seq=%d string=%q, want decimal 10", err, seq, flag.String())
	}
	if flag.Type() != "uint64" || (SeqFlag{}).String() != "0" {
		t.Fatalf("Type()=%q zero String()=%q", flag.Type(), (SeqFlag{}).String())
	}
}
