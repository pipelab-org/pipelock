// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/sdk/audit-packet"
)

func TestAuditPacketEndProofRequiresFinalRunClose(t *testing.T) {
	t.Parallel()

	run := newCompletenessFixture(t)
	fix := &fixture{
		receipts: []receipt.Receipt{run.open("run-audit-packet-proof", "open-audit-packet-proof")},
		keyHex:   run.keyHex,
	}
	fix.receipts = append(fix.receipts, run.close("run-audit-packet-proof", "open-audit-packet-proof"))

	t.Run("complete run close proves end", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		fix.writePacketDir(t, dir, nil)

		report, code := auditPacketJSON(t, "--key", fix.keyHex, dir)
		if code != cliutil.ExitOK || !report.Valid || !report.Trusted {
			t.Fatalf("complete run close: code=%d valid=%v trusted=%v verdict=%q", code, report.Valid, report.Trusted, report.Verdict)
		}
	})

	t.Run("tail-truncated packet summary cannot prove end", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		packetPath := fix.writePacketDir(t, dir, func(packet *auditpacket.Packet) {
			packet.Summary.Totals.Allow = len(fix.receipts)
		})
		truncateLastLine(t, filepath.Join(dir, "evidence.jsonl"))
		rewritePacketSummary(t, packetPath, 1, 1)

		report, code := auditPacketJSON(t, "--key", fix.keyHex, dir)
		if code != endproof.ExitPrefix {
			t.Fatalf("tail-truncated packet exit=%d, want %d; report=%+v", code, endproof.ExitPrefix, report)
		}
		if report.Valid || report.Trusted || report.Verdict == auditpacket.VerdictValid {
			t.Fatalf("tail-truncated packet claimed success: valid=%v trusted=%v verdict=%q", report.Valid, report.Trusted, report.Verdict)
		}
		if report.Summary.ReceiptCount != 1 || report.Summary.Totals["allow"] != 1 {
			t.Fatalf("summary=%+v, want verified prefix counts", report.Summary)
		}
	})

	t.Run("complete structural opt in does not promote signer trust", func(t *testing.T) {
		dir := t.TempDir()
		fix.writePacketDir(t, dir, func(packet *auditpacket.Packet) {
			packet.Verifier.Verdict = auditpacket.VerdictSelfConsistentOnly
			packet.Verifier.Trusted = false
		})
		report, code := auditPacketJSON(t, "--key", fix.keyHex, "--allow-self-consistent-only", dir)
		if code != cliutil.ExitOK || !report.Valid || report.Trusted {
			t.Fatalf("complete structural opt-in: code=%d report=%+v", code, report)
		}
	})

	t.Run("head-cut chain fails integrity", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		packetPath := fix.writePacketDir(t, dir, func(packet *auditpacket.Packet) {
			packet.Summary.Totals.Allow = len(fix.receipts)
		})
		truncateFirstLine(t, filepath.Join(dir, "evidence.jsonl"))
		rewritePacketSummary(t, packetPath, 1, 1)

		report, code := auditPacketJSON(t, "--key", fix.keyHex, dir)
		if code == cliutil.ExitOK || code == endproof.ExitPrefix {
			t.Fatalf("head-cut chain exit=%d, want integrity failure; report=%+v", code, report)
		}
		if report.Valid || report.Trusted {
			t.Fatalf("head-cut chain claimed success: valid=%v trusted=%v", report.Valid, report.Trusted)
		}
	})
}

func TestAuditPacketEndProofConformanceManifest(t *testing.T) {
	root := filepath.Join("..", "..", "sdk", "conformance", "testdata", "end-proof")
	manifestBytes, err := os.ReadFile(filepath.Clean(filepath.Join(root, "expect.json")))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Key         string `json:"key"`
		AuditPacket []struct {
			Name      string `json:"name"`
			File      string `json:"file"`
			Exit      int    `json:"exit"`
			Integrity string `json:"integrity"`
			Status    string `json:"status"`
			Proven    bool   `json:"proven"`
		} `json:"audit_packet"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.AuditPacket) == 0 || manifest.Key == "" {
		t.Fatal("end-proof manifest has no audit-packet cases or signer key")
	}

	for _, expected := range manifest.AuditPacket {
		t.Run(expected.Name, func(t *testing.T) {
			dir := t.TempDir()
			writeAuditPacketFixture(t, dir, filepath.Join(root, expected.File), manifest.Key)
			stdout, stderr, code := runRoot(t, "audit-packet", "--key", manifest.Key, "--json", dir)
			if code != expected.Exit {
				t.Fatalf("exit=%d want %d; stdout=%s stderr=%s", code, expected.Exit, stdout, stderr)
			}
			var report auditPacketReport
			if err := json.Unmarshal([]byte(stdout), &report); err != nil {
				t.Fatalf("decode report: %v; stdout=%s", err, stdout)
			}
			if report.Integrity != expected.Integrity || report.Status != expected.Status || report.EndProof.Proven != expected.Proven {
				t.Fatalf("report integrity=%q status=%q end_proven=%v; want %q %q %v", report.Integrity, report.Status, report.EndProof.Proven, expected.Integrity, expected.Status, expected.Proven)
			}
		})
	}
}

func writeAuditPacketFixture(t *testing.T, dir, evidencePath, signerKey string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(evidencePath))
	if err != nil {
		t.Fatal(err)
	}
	// Build the editable packet from supplied receipt fields, including a
	// head-cut fixture. The CLI, rather than this fixture helper, must reject
	// its missing recorder and receipt genesis links.
	receipts, err := receipt.ExtractReceiptsBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	chain := receipt.VerifyChain(receipts, signerKey)
	fix := newFixture(t, 0)
	packet := fix.basePacket(len(receipts))
	packet.Verifier.SignerKey = signerKey
	packet.Verifier.ReceiptCount = len(receipts)
	packet.Verifier.RootHash = chain.RootHash
	packet.Verifier.FinalSeq = len(receipts) - 1
	totals := computeTotals(receipts)
	packet.Summary.Totals.Allow = totals["allow"]
	packet.Summary.Totals.Block = totals["block"]
	packet.Summary.Totals.Warn = totals["warn"]
	packet.Summary.Totals.Ask = totals["ask"]
	packet.Summary.Totals.Strip = totals["strip"]
	packet.Summary.Totals.Forward = totals["forward"]
	packet.Summary.Totals.Redirect = totals["redirect"]
	packet.Summary.Totals.Other = totals["other"]
	if err := os.WriteFile(filepath.Clean(filepath.Join(dir, "evidence.jsonl")), data, 0o600); err != nil {
		t.Fatal(err)
	}
	packetBytes, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Clean(filepath.Join(dir, "packet.json")), packetBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Clean(filepath.Join(dir, "verifier.txt")), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(receipts) == 0 {
		t.Fatal("conformance evidence contains no action receipts")
	}
}

func truncateLastLine(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	cut := bytes.LastIndexByte(data[:len(data)-1], '\n')
	if cut < 0 {
		t.Fatal("evidence has no preceding line")
	}
	if err := os.WriteFile(filepath.Clean(path), data[:cut+1], 0o600); err != nil {
		t.Fatal(err)
	}
}

func truncateFirstLine(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	cut := bytes.IndexByte(data, '\n')
	if cut < 0 {
		t.Fatal("evidence has no newline")
	}
	if err := os.WriteFile(filepath.Clean(path), data[cut+1:], 0o600); err != nil {
		t.Fatal(err)
	}
}

func rewritePacketSummary(t *testing.T, path string, receiptCount, allowCount int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var packet auditpacket.Packet
	if err := json.Unmarshal(data, &packet); err != nil {
		t.Fatal(err)
	}
	packet.Summary.ReceiptCount = receiptCount
	packet.Summary.Totals = auditpacket.Totals{Allow: allowCount}
	data, err = json.MarshalIndent(packet, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Clean(path), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
