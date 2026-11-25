// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestEvidenceCommandsRefuseReceiptV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, _ string) {
		const session = "proxy"
		output := filepath.Join(t.TempDir(), "output.json")
		cmd := &cobra.Command{}
		_, doctorErr := runEvidenceDoctor(dir)
		repair := repairGroupTransitionCmd()
		repair.SetArgs([]string{"--dir", dir, "--group", "example", "--key-file", output})
		cases := []struct {
			command, reader string
			err             error
		}{
			{"view", "the evidence scorecard", runView(cmd, viewOptions{receiptDir: dir, outFile: output})},
			{"serve", "the evidence scorecard", runServe(cmd, serveOptions{receiptDir: dir})},
			{"doctor", "the evidence doctor", doctorErr},
			{"expire", "the legacy evidence reader", runExpire(cmd, expireOptions{receiptDir: dir}, false)},
			{"repair-group-transition", "the legacy evidence reader", repair.Execute()},
			{"compact", "the legacy evidence reader", runCompact(cmd, compactOptions{receiptDir: dir, sessionID: session})},
			{"inspect-epochs", "the legacy evidence reader", runInspectEpochs(cmd, inspectEpochsOptions{receiptDir: dir, sessionID: session, outFile: output})},
			{"verify-epoch-pin", "the legacy evidence reader", runVerifyEpochPin(cmd, verifyEpochPinOptions{receiptDir: dir, sessionID: session, pinFile: output, pinSHA256: strings.Repeat("0", 64)})},
			{"inventory-legacy-epochs", "the legacy evidence reader", runInventoryLegacyEpochs(cmd, legacyInventoryOptions{receiptDir: dir, sessionID: session, outFile: output})},
			{"verify-legacy-epoch-inventory", "the legacy evidence reader", runVerifyLegacyEpochInventory(cmd, verifyLegacyInventoryOptions{receiptDir: dir, sessionID: session, inventoryFile: output})},
		}
		for _, tc := range cases {
			testreceipt.RequiresV3Refusal(t, tc.err, "evidence "+tc.command, tc.reader)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatalf("refused command created output: %v", err)
		}
	})
}
