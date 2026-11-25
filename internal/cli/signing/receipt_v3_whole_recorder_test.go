// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestVerifyReceiptV3RefusesWholeRecorderOptions(t *testing.T) {
	for _, fixture := range []string{"g01-valid-line", "g01-damaged-first-line"} {
		t.Run(fixture, func(t *testing.T) {
			dir := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "v3", fixture)
			for _, flag := range []string{"--whole-recorder", "--require-seal"} {
				t.Run(flag, func(t *testing.T) {
					cmd := VerifyReceiptCmd()
					cmd.SetArgs([]string{"--chain", dir, flag})
					err := cmd.Execute()
					if err == nil || cliutil.ExitCodeOf(err) != cliutil.ExitConfig ||
						!strings.Contains(err.Error(), flag+": receipt v3 has no whole-recorder proof in this release") ||
						!strings.Contains(err.Error(), "checking the log against that root is not offered yet") ||
						strings.Contains(err.Error(), "--expect-head") {
						t.Fatalf("unexpected error: %v", err)
					}
				})
			}
		})
	}
}

func TestReceiptRotationEndorseRefusesV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, _ string) {
		output := filepath.Join(t.TempDir(), "endorsement.json")
		cmd := receiptRotationEndorseCmd(time.Now)
		cmd.SetArgs([]string{
			"--chain", dir, "--prior-key-file", "prior.key", "--new-key-file", "new.key",
			"--root-key", "root.pub", "--out", output,
		})
		testreceipt.RequiresV3Refusal(t, cmd.Execute(), "receipt rotation endorse", "legacy receipt rotation")
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatalf("refused rotation created output: %v", err)
		}
	})
}
