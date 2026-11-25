// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestLearnRefusesV3BeforeWriting(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, _ string) {
		out := filepath.Join(dir, "receipts.jsonl")
		report := filepath.Join(t.TempDir(), "report.json")
		cmd := &cobra.Command{}
		for _, tc := range []struct {
			name string
			err  error
		}{
			{"shadow", runShadow(cmd, shadowFlags{recorderDir: dir, outJSONPath: report})},
			{"ratify", runRatify(cmd, ratifyFlags{receiptOut: out})},
			{"forget", runForget(cmd, forgetFlags{receiptOut: out})},
			{"promote", runPromote(cmd, lifecycleFlags{receiptOut: out})},
			{"rollback", runRollback(cmd, lifecycleFlags{storeDir: dir})},
		} {
			testreceipt.RequiresV3Refusal(t, tc.err, "learn "+tc.name, "learn lifecycle receipts")
		}
		for _, p := range []string{out, report, filepath.Join(dir, defaultLifecycleReceiptOut)} {
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Fatalf("refused command created %s: %v", p, err)
			}
		}
	})
}
