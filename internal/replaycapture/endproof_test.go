// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestCaptureProvesRunEnd(t *testing.T) {
	eng := newTestEngine(t)
	cs, err := eng.Capture(DefaultScenarios()[1])
	if err != nil {
		t.Fatal(err)
	}
	if got := endproof.ActionEvidence(cs.Receipts); len(got) == 0 {
		t.Fatal("capture has no authenticated run end")
	}
	entries, err := recorder.ReadHistoryEntries(cs.EvidenceFile)
	if err != nil {
		t.Fatal(err)
	}
	var decisions int
	for _, entry := range entries {
		if entry.Type == "decision" {
			decisions++
		}
	}
	if decisions == 0 {
		t.Fatal("the proxy must retain operational decisions under the same run session as receipts")
	}
	data, err := json.Marshal(cs.Receipts[len(cs.Receipts)-1])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("gallery close receipt: %s", data)
}

func TestVerifyPacketRequiresEndProof(t *testing.T) {
	eng := newTestEngine(t)
	cs, err := eng.Capture(DefaultScenarios()[0])
	if err != nil {
		t.Fatal(err)
	}
	// Retain every signed action except the close; update the unsigned packet
	// claims so a summary mismatch cannot stand in for endpoint verification.
	if len(endproof.ActionEvidence(cs.Receipts)) > 0 {
		cs.Receipts = cs.Receipts[:len(cs.Receipts)-1]
	}
	chain := receipt.VerifyChain(cs.Receipts, eng.PublicKeyHex())
	if !chain.Valid || len(cs.Receipts) < 2 {
		t.Fatalf("prefix integrity/positive action control: %+v", chain)
	}
	cs.ReceiptCount, cs.FinalSeq, cs.RootHash, cs.ChainResult = len(cs.Receipts), chain.FinalSeq, chain.RootHash, chain
	var evidence bytes.Buffer
	for _, r := range cs.Receipts {
		if err := json.NewEncoder(&evidence).Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	cs.EvidenceFile = filepath.Join(t.TempDir(), "prefix.jsonl")
	if err := os.WriteFile(cs.EvidenceFile, evidence.Bytes(), filePerm); err != nil {
		t.Fatal(err)
	}
	res, err := AssemblePacket(cs, t.TempDir(), fixedStamp())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := os.ReadFile(filepath.Join(res.PacketDir, artifactPacketName))
	if err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"directory": VerifyPacketDir(res.PacketDir, eng.PublicKeyHex()),
		"browser":   VerifyPacketBytes(packet, evidence.Bytes(), eng.PublicKeyHex()),
	} {
		if err == nil || !strings.Contains(err.Error(), endproof.Prefix) {
			t.Errorf("%s: got %v, want %s", name, err, endproof.Prefix)
		}
	}
}

func TestPublicGallerySessionClose(t *testing.T) {
	eng := newTestEngine(t)
	cs, err := eng.Capture(DefaultScenarios()[0])
	if err != nil {
		t.Fatal(err)
	}
	last := cs.Receipts[len(cs.Receipts)-1].ActionRecord
	if last.SessionControl == nil || last.SessionControl.Close == nil {
		t.Fatal("capture did not emit close")
	}
	for name, mutate := range map[string]func(*receipt.ActionRecord){
		"positive":      func(*receipt.ActionRecord) {},
		"target":        func(ar *receipt.ActionRecord) { ar.Target = "https://api.vendor.example/private" },
		"nonce":         func(ar *receipt.ActionRecord) { ar.SessionControl.Close.OpenNonce = "private" },
		"run mismatch":  func(ar *receipt.ActionRecord) { ar.SessionControl.Close.RunNonce = strings.Repeat("0", 32) },
		"sequence":      func(ar *receipt.ActionRecord) { ar.SessionControl.Close.FinalSeq++ },
		"count":         func(ar *receipt.ActionRecord) { ar.SessionControl.Close.ReceiptCount++ },
		"head":          func(ar *receipt.ActionRecord) { ar.SessionControl.Close.RootHash = strings.Repeat("0", 64) },
		"reason":        func(ar *receipt.ActionRecord) { ar.SessionControl.Close.CloseReason = "operator detail" },
		"fsync":         func(ar *receipt.ActionRecord) { ar.SessionControl.Close.FsyncErrorsGated++ },
		"durability":    func(ar *receipt.ActionRecord) { ar.SessionControl.Close.DurabilityBlocks++ },
		"context":       func(ar *receipt.ActionRecord) { ar.SessionID = "private" },
		"policy":        func(ar *receipt.ActionRecord) { ar.PolicyHash = "private" },
		"pattern":       func(ar *receipt.ActionRecord) { ar.Pattern = "private" },
		"method":        func(ar *receipt.ActionRecord) { ar.Method = "private" },
		"extra control": func(ar *receipt.ActionRecord) { ar.SessionControl.Open = &receipt.SessionOpen{} },
		"missing close": func(ar *receipt.ActionRecord) { ar.SessionControl.Close = nil },
	} {
		t.Run(name, func(t *testing.T) {
			ar := last
			control := *last.SessionControl
			closing := *control.Close
			ar.SessionControl = &control
			ar.SessionControl.Close = &closing
			mutate(&ar)
			err := ValidateReceiptPublicSafe(ar)
			if (err == nil) != (name == "positive") {
				t.Fatalf("public-safety gate: %v", err)
			}
		})
	}
}
