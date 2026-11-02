// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"strings"
	"testing"
)

// The standard uint64 flag reads "010" as 8 and "0x2" as 2; every verifier
// reads an endpoint pin as decimal instead.
func TestVerifyReceiptExpectSeqRefusesNonDecimalSpellings(t *testing.T) {
	for _, text := range []string{"0x2", "0o2", "+2", "1_0"} {
		t.Run(text, func(t *testing.T) {
			cmd := VerifyReceiptCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			cmd.SetArgs([]string{"unused.jsonl", "--expect-seq", text})
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "decimal digits") {
				t.Fatalf("err = %v, want decimal-digits refusal", err)
			}
		})
	}
}
