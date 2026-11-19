// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
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

func TestServerReloadReceiptFormatRequiresRestart(t *testing.T) {
	s, stderr := newRequireReceiptsReloadServer(t)
	before := s.proxy.CurrentConfig()
	unchanged := before.Clone()
	if err := s.Reload(unchanged); err != nil {
		t.Fatal(err)
	}
	const warning = "flight_recorder.receipt_format changed; restart required"
	if stderr.contains(warning) {
		t.Fatal("unchanged receipt format reported a restart")
	}
	update := before.Clone()
	update.FlightRecorder.ReceiptFormat = config.ReceiptFormatV3
	update.FetchProxy.TimeoutSeconds++
	if err := s.Reload(update); err != nil {
		t.Fatal(err)
	}
	live := s.proxy.CurrentConfig()
	if live.FlightRecorder.ReceiptFormat != before.FlightRecorder.ReceiptFormat ||
		live.FetchProxy.TimeoutSeconds != update.FetchProxy.TimeoutSeconds || !stderr.contains(warning) {
		t.Fatalf("receipt format or unrelated settings changed incorrectly: %+v, %s", live.FlightRecorder, stderr.String())
	}
}

func TestServerV3CoverageRequiresRestart(t *testing.T) {
	dir := t.TempDir()
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "signer.key")
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeServerTestConfig(t, fmt.Sprintf(
		"mode: balanced\nflight_recorder:\n  enabled: true\n  receipt_format: v3\n  require_receipts: true\n  dir: %q\n  signing_key_path: %q\n", dir, keyPath))
	s, err := NewServer(ServerOpts{ConfigFile: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	if s.receiptWriter == nil || s.liveReceiptEmitter() != nil || s.liveV2ReceiptEmitter() != nil {
		t.Fatal("v3 startup did not select a single receipt writer")
	}
	before := s.proxy.CurrentConfig()
	for _, tc := range []struct {
		field string
		edit  func(*config.Config)
	}{
		{"receipt_format", func(c *config.Config) { c.FlightRecorder.ReceiptFormat = config.ReceiptFormatLegacy }},
		{"require_receipts", func(c *config.Config) { c.FlightRecorder.RequireReceipts = false }},
		{"redact", func(c *config.Config) { c.FlightRecorder.Redact = !c.FlightRecorder.Redact }},
		{"surfaces", func(c *config.Config) { c.ForwardProxy.Enabled = !c.ForwardProxy.Enabled }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			candidate := before.Clone()
			tc.edit(candidate)
			if err := s.Reload(candidate); err == nil || !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), "restart required") {
				t.Fatalf("coverage change did not require restart: %v", err)
			}
			if s.proxy.CurrentConfig() != before {
				t.Fatal("rejected reload replaced the live config")
			}
		})
	}
	candidate := before.Clone()
	candidate.FetchProxy.TimeoutSeconds++
	if err := s.Reload(candidate); err != nil {
		t.Fatal(err)
	}
	if s.proxy.CurrentConfig().FetchProxy.TimeoutSeconds != candidate.FetchProxy.TimeoutSeconds ||
		s.liveReceiptEmitter() != nil || s.liveV2ReceiptEmitter() != nil {
		t.Fatal("unrelated reload did not preserve the v3 writer selection")
	}
}
