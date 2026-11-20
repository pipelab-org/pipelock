// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestGuardRefusesOversizedNativePredecessor(t *testing.T) {
	t.Run("single", func(t *testing.T) {
		testGuardRefusesOversizedNativePredecessor(t, 1)
	})
	t.Run("group", func(t *testing.T) {
		testGuardRefusesOversizedNativePredecessor(t, 2)
	})
}

func testGuardRefusesOversizedNativePredecessor(t *testing.T, chains int) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "evidence")
	keyPath := filepath.Join(root, "receipt.key")
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	chainLine := ""
	if chains > 1 {
		chainLine = fmt.Sprintf("  receipt_chains: %d\n  sign_checkpoints: true\n", chains)
	}
	opts := ServerOpts{
		ConfigFile: writeServerTestConfig(t, fmt.Sprintf("mode: balanced\nflight_recorder:\n  enabled: true\n  require_receipts: true\n%s  dir: %q\n  signing_key_path: %q\n", chainLine, dir, keyPath)),
		Stdout:     io.Discard, Stderr: io.Discard,
	}
	first, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.sealTranscriptRoot(); err != nil {
		first.cleanup()
		t.Fatal(err)
	}
	first.cleanup()
	paths, err := filepath.Glob(filepath.Join(dir, "ael", "*", "recorders", "*.jsonl"))
	if err != nil || len(paths) != chains {
		t.Fatalf("native streams = %v, err = %v", paths, err)
	}
	if err := os.Truncate(paths[0], (256<<20)+1); err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = dir
	cfg.FlightRecorder.SigningKeyPath = keyPath
	cfg.FlightRecorder.RequireReceipts = true
	cfg.FlightRecorder.SignCheckpoints = true
	cfg.FlightRecorder.ReceiptChains = chains
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	evidence, err := newGuardEvidence(t.Context(), cfg, sc, metrics.New(), io.Discard)
	if evidence != nil {
		evidence.close()
	}
	if !errors.Is(err, ael.ErrStreamTooLarge) || !strings.Contains(err.Error(), "set flight_recorder.dir to a new empty directory") {
		t.Fatalf("Guard startup = %v, evidence open = %v", err, evidence != nil)
	}
}
