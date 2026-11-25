// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
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
