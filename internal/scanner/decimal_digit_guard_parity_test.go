// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

func TestDecimalCharacterCodeParserReferenceParity(t *testing.T) {
	inputs := []string{"", "0", "-0", "+65", "65.0", "6.5e1", ".65e2", "0x1.04p6", "0x41", "1_0", "NaN", "Inf", "-Inf", "1114111", "1114112", "55295", "55296", "57343", "57344", "2147483647", "2147483648", "-2147483648", "1e9999", "1e-9999", "not-a-number", strings.Repeat("0", 256) + "65", "1" + strings.Repeat("0", 256), "\xff65"}
	rnd := rand.New(rand.NewSource(28136)) // #nosec G404 -- deterministic parser parity.
	for range 2000 {
		b := make([]byte, rnd.Intn(24))
		for i := range b {
			b[i] = byte(rnd.Uint32() & 0xff)
		}
		inputs = append(inputs, string(b), strconv.Itoa(rnd.Intn(1<<22)-(1<<21)))
	}
	accepted, rejected := 0, 0
	for _, input := range inputs {
		want, wantOK := func() (rune, bool) {
			if code, err := strconv.ParseInt(input, 10, 32); err == nil {
				return validDecimalCharacterCode(code)
			}
			value, err := strconv.ParseFloat(input, 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value {
				return 0, false
			}
			return validDecimalCharacterCode(int64(value))
		}()
		got, gotOK := parseDecimalCharacterCode(input)
		if got != want || gotOK != wantOK {
			t.Fatalf("parser differs for %q: got %d/%v, want %d/%v", input, got, gotOK, want, wantOK)
		}
		if gotOK {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatal("parser parity needs accepted and rejected fields")
	}
}

func TestDecimalDigitGuardReferenceParity(t *testing.T) {
	inputs := []string{
		"", "ordinary text", "\xff\x00ordinary", "１２３４５６７８９", "NaN Inf -Inf +Inf",
		"GET /v1/models?stream=true HTTP/1.1 host api.vendor.example accept application/json",
		"104,105", "00000000", "11111111", "0,0,0,0,0,0,0", "0,0,0,0,0,0,0,0", "0,0,0,0,0,0,0,0,0",
		"65.0,65.0,65.0,65.0,65.0,65.0,65.0,65.0",
		"6.5e1,6.5e1,6.5e1,6.5e1,6.5e1,6.5e1,6.5e1,6.5e1",
		"+65,+65,+65,+65,+65,+65,+65,+65", "-0,-0,-0,-0,-0,-0,-0,-0",
		decimalCharacterCodes("secret-value", ","),
		decimalCharacterCodes("secret-value", " "),
		decimalCharacterCodes("first-run", ",") + ",2.5," + decimalCharacterCodes("second-run", ","),
		decimalCharacterCodes("secret-value", ",") + ",-1,104,105",
		decimalCharacterCodes("secret-value", ",") + ",1114112",
		decimalCharacterCodes("secret-", ",") + ",55296," + decimalCharacterCodes("value", ","),
		strings.Repeat("ordinary prose with no numbers. ", 128),
	}
	fields := []string{"0", "65", "65.0", "6.5e1", "+65", "-0", "-1", "2.5", "1114112", "55296", "NaN", "Inf", "e", "E", "", "\xff", "１２", "0000", "0x41", "1e9999", "1e-9999"}
	separators := []string{" ", ",", ", ", "[", "]", ";", ":", "_", "\u200B"}
	rnd := rand.New(rand.NewSource(47318)) // #nosec G404 -- deterministic parity corpus.
	for range 2000 {
		var input strings.Builder
		for range rnd.Intn(20) {
			input.WriteString(fields[rnd.Intn(len(fields))])
			input.WriteString(separators[rnd.Intn(len(separators))])
		}
		inputs = append(inputs, input.String())
	}
	guardEmpty, parsedEmpty, emitted := 0, 0, 0
	for _, input := range inputs {
		got := decodeDecimalCharacterCodes(input)
		want := referenceDecimalBeforeDigitGuard(input)
		if got != want {
			t.Fatalf("decimal output differs for %q: got %q, want %q", input, got, want)
		}
		digits := 0
		for i := range len(input) {
			if input[i] >= '0' && input[i] <= '9' {
				digits++
			}
		}
		switch {
		case digits < minDecimalCodeRun:
			guardEmpty++
			if want != "" {
				t.Fatal("the original decoder emitted a run with too few digit bytes")
			}
		case got == "":
			parsedEmpty++
		default:
			emitted++
		}
	}
	if guardEmpty == 0 || parsedEmpty == 0 || emitted == 0 {
		t.Fatalf("vacuous decimal parity: guarded=%d parsed-empty=%d emitted=%d", guardEmpty, parsedEmpty, emitted)
	}
	t.Logf("compared %d complete decimal outputs: guarded=%d parsed-empty=%d emitted=%d", len(inputs), guardEmpty, parsedEmpty, emitted)
}

// Frozen decoder before the digit-count guard.
func referenceDecimalBeforeDigitGuard(numeric string) string {
	var out strings.Builder
	var run strings.Builder
	runLen := 0
	flush := func() {
		if runLen >= minDecimalCodeRun {
			if out.Len() > 0 {
				out.WriteByte('\n')
			}
			out.WriteString(run.String())
		}
		run.Reset()
		runLen = 0
	}
	fields := strings.FieldsFunc(numeric, isDecimalCodeSeparator)
	for _, field := range fields {
		code, ok := parseDecimalCharacterCode(field)
		if !ok {
			flush()
			continue
		}
		run.WriteRune(code)
		runLen++
	}
	flush()
	return out.String()
}
