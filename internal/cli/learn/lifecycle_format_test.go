// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPromoteRefusesSwitchedReceiptDirectoryBeforeCreatingStore(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "example.receipt-v3.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(t.TempDir(), "store")
	err := runPromote(nil, lifecycleFlags{storeDir: store, receiptOut: filepath.Join(dir, "activation-receipts.jsonl")})
	if err == nil || !strings.Contains(err.Error(), "new evidence directory after a v3 switch") {
		t.Fatalf("expected legacy write refusal, got %v", err)
	}
	if _, err := os.Stat(store); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("contract store was changed before receipt format check: %v", err)
	}
}
