// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestDeferredReleaseCorrectiveReceiptPrecedesTerminalJournal(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)
	opts := MCPProxyOpts{
		ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2,
		RequireReceipts: true, PolicyHash: mcpTestPolicyHash, Transport: deferred.SurfaceMCPStdio,
	}
	if err := h.v1.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	admission, err := opts.admitNativeRequest()
	if err != nil {
		t.Fatal(err)
	}
	defer admission.ReleaseNativeAdmission()
	opts.nativeAdmission = admission
	opts, finishHeld, err := opts.splitDeferredAdmission()
	if err != nil {
		t.Fatal(err)
	}
	defer finishHeld()
	var settlement deferredReceiptSettlement
	writes := 0
	manager := deferred.NewManager(deferred.Config{
		Enabled: true, JournalPath: filepath.Join(t.TempDir(), "journal.jsonl"),
		JournalWriteGuard: func(write func() error) error {
			writes++
			if writes == 3 {
				return io.ErrClosedPipe
			}
			if writes == 4 && (!settlement.done || settlement.decision != config.ActionBlock) {
				t.Fatal("terminal block attempted before corrective receipt")
			}
			return write()
		},
	})
	if err := manager.Hold(deferred.HeldAction{
		DeferID: "held", ActionID: "held", Target: "tool", Method: "tools/call",
		AfterJournal: func(res deferred.Resolution) error { return settlement.commitAllow(opts, io.Discard, res) },
		Resolve: func(res deferred.Resolution) {
			if res.FinalDecision != config.ActionBlock {
				t.Fatalf("final = %s, want block", res.FinalDecision)
			}
			if err := settlement.ensure(opts, io.Discard, res); err != nil {
				t.Fatal(err)
			}
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Resolve("held", config.ActionAllow, deferred.SourceOperator); err != nil {
		t.Fatal(err)
	}
	finishHeld()
	admission.ReleaseNativeAdmission()
	records := verifyMCPNativeClose(t, h.v1, h.dir)
	if records != 2 {
		t.Fatalf("deferred corrective release: wrote %d native records, want 2", records)
	}
	assertMCPNativeRecordBudget(t, "deferred corrective release", records, nativeMCPPendingRecords)
	if err := h.rec.Close(); err != nil {
		t.Fatal(err)
	}
	resolutions := 0
	for _, r := range readActionReceipts(t, h.dir) {
		if r.ActionRecord.DecisionPhase != receipt.DecisionPhaseResolution {
			continue
		}
		i := resolutions
		resolutions++
		want := config.ActionAllow
		if i == 1 {
			want = config.ActionBlock
		}
		if i > 1 || r.ActionRecord.Verdict != want {
			t.Fatalf("receipt %d verdict = %s, want %s", i, r.ActionRecord.Verdict, want)
		}
	}
	if resolutions != 2 {
		t.Fatalf("resolution receipts = %d, want 2 with no duplicate from Resolve", resolutions)
	}
	if pending, err := deferred.PendingJournal(manager.JournalPath()); err != nil || len(pending) != 0 {
		t.Fatalf("pending = %d, err=%v; want 0", len(pending), err)
	}
}
