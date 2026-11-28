// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestAnchorReceiptsRefusesV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, path string) {
		testreceipt.RequiresV3Refusal(t, runReceipts(io.Discard, dir, receiptsOptions{asDir: true}), "anchor receipts", "the receipt anchor")
		testreceipt.RequiresV3Refusal(t, runReceipts(io.Discard, path, receiptsOptions{}), "anchor receipts", "the receipt anchor")
	})
}

func TestAnchorReceiptsRefusesV3InResolvedSubdir(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "location-a")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	testreceipt.V3(t, sub, false)
	if err := os.WriteFile(filepath.Join(sub, "evidence-proxy-0.jsonl"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	testreceipt.RequiresV3Refusal(t, runReceipts(io.Discard, root, receiptsOptions{asDir: true}), "anchor receipts", "the receipt anchor")
}
