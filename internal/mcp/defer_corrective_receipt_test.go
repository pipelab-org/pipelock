// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestDeferredReleaseCorrectiveReceiptPrecedesTerminalJournal(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)
	opts := MCPProxyOpts{
		ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2,
		RequireReceipts: true, PolicyHash: mcpTestPolicyHash, Transport: deferred.SurfaceMCPStdio,
	}
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
	if err := h.rec.Close(); err != nil {
		t.Fatal(err)
	}
	for i, r := range readActionReceipts(t, h.dir) {
		want := config.ActionAllow
		if i == 1 {
			want = config.ActionBlock
		}
		if i > 1 || r.ActionRecord.Verdict != want {
			t.Fatalf("receipt %d verdict = %s, want %s", i, r.ActionRecord.Verdict, want)
		}
	}
	if records := readActionReceipts(t, h.dir); len(records) != 2 {
		t.Fatalf("resolution receipts = %d, want 2 with no duplicate from Resolve", len(records))
	}
	if pending, err := deferred.PendingJournal(manager.JournalPath()); err != nil || len(pending) != 0 {
		t.Fatalf("pending = %d, err=%v; want 0", len(pending), err)
	}
}

type deferredReleaseFailWriter struct{}

func (deferredReleaseFailWriter) WriteMessage([]byte) error { return io.ErrClosedPipe }

func TestDeferredStdioReleaseRecordsUpstreamWriteFailure(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)
	manager := newDeferKillManager(t)
	policyCfg := deferApprovalPolicy(config.DeferResolverProfile{})
	policyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
	opts := MCPProxyOpts{
		Scanner: testInputScanner(t), PolicyCfg: policyCfg, DeferManager: manager,
		ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2, RequireReceipts: true,
		PolicyHash: mcpTestPolicyHash, Transport: deferred.SurfaceMCPStdio,
	}
	input, feed := io.Pipe()
	done := make(chan struct{})
	tracker := NewRequestTracker()
	go func() {
		defer close(done)
		ForwardScannedInput(transport.NewStdioReader(input), deferredReleaseFailWriter{}, io.Discard,
			config.ActionWarn, config.ActionBlock, make(chan BlockedRequest, 1), nil, tracker, opts)
	}()
	t.Cleanup(func() {
		_ = feed.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("stdio input loop did not stop")
		}
	})
	if _, err := io.WriteString(feed, deferKillTestCall); err != nil {
		t.Fatal(err)
	}
	testwait.For(t, 5*time.Second, func() bool { return len(manager.Snapshot()) == 1 }, "deferred stdio hold")
	hold := manager.Snapshot()[0]
	if err := manager.Resolve(hold.DeferID, config.ActionAllow, deferred.SourceApproval); err != nil {
		t.Fatal(err)
	}
	if err := h.rec.Close(); err != nil {
		t.Fatal(err)
	}
	var resolutions []receipt.ActionRecord
	for _, r := range readActionReceipts(t, h.dir) {
		if r.ActionRecord.DecisionPhase == receipt.DecisionPhaseResolution {
			resolutions = append(resolutions, r.ActionRecord)
		}
	}
	if len(resolutions) != 2 {
		t.Fatalf("resolution receipt count = %d, want approval and upstream write failure", len(resolutions))
	}
	approved, failed := resolutions[0], resolutions[1]
	if approved.Verdict != config.ActionAllow || failed.Verdict != config.ActionBlock ||
		failed.Pattern != "upstream_write_failed" || failed.ResolutionSource != deferred.SourceCancel ||
		failed.DeferID != hold.DeferID || failed.ParentActionID != hold.ActionID {
		t.Fatalf("approved=%+v failed=%+v", approved, failed)
	}
	if tracker.HasPending() {
		t.Fatal("failed write left a pending upstream response")
	}
}
