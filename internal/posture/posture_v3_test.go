// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/evidence/receiptinput"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

// Posture counts receipts in the recorder directory. A receipt-profile stream
// must refuse that count instead of reporting it as zero receipts.
func TestCollectFlightRecorderEvidenceRefusesReceiptProfile(t *testing.T) {
	fixtures := map[string]func(t *testing.T, dir string){
		"signed":  func(t *testing.T, dir string) { testreceipt.V3(t, dir, false) },
		"damaged": func(t *testing.T, dir string) { testreceipt.V3(t, dir, true) },
		"renamed": func(t *testing.T, dir string) {
			path, _ := testreceipt.V3(t, t.TempDir(), false)
			raw, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), append([]byte("\n "), raw...), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"nested": func(t *testing.T, dir string) {
			child := filepath.Join(dir, "child")
			if err := os.Mkdir(child, 0o750); err != nil {
				t.Fatal(err)
			}
			testreceipt.V3(t, child, false)
		},
	}
	for name, setup := range fixtures {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setup(t, dir)
			cfg := config.Defaults()
			cfg.FlightRecorder.Dir = dir
			_, err := collectFlightRecorderEvidence(cfg)
			if !errors.Is(err, receiptinput.ErrUnsupported) || !strings.Contains(err.Error(), "pipelock verify-receipt --chain") {
				t.Fatalf("collectFlightRecorderEvidence() = %v, want receipt-profile refusal naming verify-receipt", err)
			}

			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if capsule, err := Emit(cfg, Options{SigningKey: priv}); err == nil || capsule != nil {
				t.Fatalf("Emit() signed a capsule over receipt-profile evidence: %v", err)
			}
		})
	}
}
