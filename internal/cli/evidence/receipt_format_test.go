// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/evidence/receiptinput"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
	"github.com/luckyPipewrench/pipelock/internal/verification"
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

func TestEvidenceCommandsRefuseV3RootWithLegacySubdirAndNestedV3Doctor(t *testing.T) {
	// Layout 1: v3 at root, legacy operational shard in a subdirectory.
	// ResolveEvidenceLocation skips root because root has no legacy shards and
	// resolves the legacy subdirectory; commands must refuse root before acting.
	root := t.TempDir()
	testreceipt.V3(t, root, false)
	sub := filepath.Join(root, "operational")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "evidence-proxy-0.jsonl"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "output.json")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	for _, tc := range []struct {
		command, reader string
		err             error
	}{
		{"view", "the evidence scorecard", runView(cmd, viewOptions{receiptDir: root, outFile: output})},
		{"serve", "the evidence scorecard", runServe(cmd, serveOptions{receiptDir: root})},
		{"compact", "the legacy evidence reader", runCompact(cmd, compactOptions{receiptDir: root, sessionID: "proxy"})},
		{"inspect-epochs", "the legacy evidence reader", runInspectEpochs(cmd, inspectEpochsOptions{receiptDir: root, sessionID: "proxy", outFile: output})},
		{"verify-epoch-pin", "the legacy evidence reader", runVerifyEpochPin(cmd, verifyEpochPinOptions{receiptDir: root, sessionID: "proxy", pinFile: output, pinSHA256: strings.Repeat("0", 64)})},
		{"inventory-legacy-epochs", "the legacy evidence reader", runInventoryLegacyEpochs(cmd, legacyInventoryOptions{receiptDir: root, sessionID: "proxy", outFile: output})},
		{"verify-legacy-epoch-inventory", "the legacy evidence reader", runVerifyLegacyEpochInventory(cmd, verifyLegacyInventoryOptions{receiptDir: root, sessionID: "proxy", inventoryFile: output})},
	} {
		testreceipt.RequiresV3Refusal(t, tc.err, "evidence "+tc.command, tc.reader)
	}

	// Layout 2: v3-only subdirectory under an otherwise empty root.
	// evidence doctor must refuse the corpus rather than reporting healthy.
	nestedRoot := t.TempDir()
	nestedV3 := filepath.Join(nestedRoot, "v3-only")
	if err := os.Mkdir(nestedV3, 0o750); err != nil {
		t.Fatal(err)
	}
	testreceipt.V3(t, nestedV3, false)
	_, doctorErr := runEvidenceDoctor(nestedRoot)
	testreceipt.RequiresV3Refusal(t, doctorErr, "evidence doctor", "the evidence doctor")
}

func TestRepairGroupTransitionGuardRunsUnderCeremonyLock(t *testing.T) {
	dir := t.TempDir()
	testreceipt.V3(t, dir, false)
	seed := sha256.Sum256([]byte("repair-guard-key"))
	key := ed25519.NewKeyFromSeed(seed[:])
	_, err := receipt.RepairReceiptGroupTransitionWithGuard(
		dir, strings.Repeat("a", 32), key, nil, verification.Options{Context: t.Context()},
		func(lockedDir string) error {
			return receiptinput.Refuse(lockedDir, "evidence repair-group-transition", "the legacy evidence reader")
		},
	)
	testreceipt.RequiresV3Refusal(t, err, "evidence repair-group-transition", "the legacy evidence reader")
}
