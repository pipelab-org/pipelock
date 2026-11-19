// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReceiptV3Selection(t *testing.T) {
	dir := t.TempDir()
	cfg := config.FlightRecorder{Dir: dir, Enabled: true, SigningKeyPath: "signer.key"}

	if selected, err := receiptV3Selected(cfg); err != nil || selected {
		t.Fatalf("empty directory with omitted setting selected v3: %v, %v", selected, err)
	}
	cfg.ReceiptFormat = config.ReceiptFormatV3
	if selected, err := receiptV3Selected(cfg); err != nil || !selected {
		t.Fatalf("explicit choice in an empty directory failed: %v, %v", selected, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "damaged.receipt-v3.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.ReceiptFormat = ""
	if selected, err := receiptV3Selected(cfg); err != nil || !selected {
		t.Fatalf("omitted choice in a switched directory failed: %v, %v", selected, err)
	}
	cfg.ReceiptChains = 2
	if _, err := receiptV3Selected(cfg); err == nil || !strings.Contains(err.Error(), "flight_recorder.receipt_format") {
		t.Fatalf("switched directory accepted multiple receipt chains: %v", err)
	}
	cfg.ReceiptChains = 1
	cfg.ReceiptFormat = config.ReceiptFormatLegacy
	if _, err := receiptV3Selected(cfg); err == nil || !strings.Contains(err.Error(), "requires a new evidence directory") {
		t.Fatalf("switched directory accepted a legacy restart: %v", err)
	}
}
