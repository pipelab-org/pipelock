// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

// An endpoint pin is read as decimal in every verifier. The standard uint64
// flag reads "010" as 8 and "0x2" as 2, which pins a different endpoint than
// the Rust, TypeScript, and Python verifiers do.
func TestExpectSeqFlagRefusesNonDecimalSpellings(t *testing.T) {
	for name, build := range map[string]func() *cobra.Command{"chain": newChainCmd, "aarp": newAARPCmd} {
		for _, text := range []string{"0x2", "0o2", "+2", "1_0", " 2"} {
			t.Run(name+"/"+text, func(t *testing.T) {
				cmd := build()
				var out bytes.Buffer
				cmd.SetOut(&out)
				cmd.SetErr(&out)
				cmd.SetArgs([]string{"unused.jsonl", "--expect-seq", text})
				assertExitCode(t, cmd.Execute(), exitUsage)
			})
		}
	}
}
