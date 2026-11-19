// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
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

func TestDeferredReleaseOutcomeFailureKeepsJournalPending(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)
	opts := MCPProxyOpts{
		ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2,
		RequireReceipts: true, PolicyHash: mcpTestPolicyHash, Transport: deferred.SurfaceMCPStdio,
	}
	h.rec.SetReceiptAppendGuardForTest(func(entry recorder.Entry) error {
		detail, ok := entry.Detail.(json.RawMessage)
		if !ok {
			return nil
		}
		r, err := receipt.Unmarshal(detail)
		if err == nil && r.ActionRecord.DecisionPhase == receipt.DecisionPhaseOutcome && r.ActionRecord.Verdict == config.ActionBlock {
			return io.ErrClosedPipe
		}
		return nil
	})
	var settlement deferredReceiptSettlement
	writes := 0
	manager := deferred.NewManager(deferred.Config{
		Enabled: true, JournalPath: filepath.Join(t.TempDir(), "journal.jsonl"),
		JournalWriteGuard: func(write func() error) error {
			writes++
			if writes == 3 {
				return io.ErrClosedPipe
			}
			return write()
		},
	})
	if err := manager.Hold(deferred.HeldAction{
		DeferID: "held", ActionID: "held", Target: "tool", Method: methodToolsCall,
		AfterJournal: func(res deferred.Resolution) error { return settlement.commitRelease(opts, io.Discard, res) },
		Resolve: func(res deferred.Resolution) {
			if res.FinalDecision != config.ActionBlock {
				t.Fatalf("final = %s, want block", res.FinalDecision)
			}
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Resolve("held", config.ActionAllow, deferred.SourceOperator); err != nil {
		t.Fatal(err)
	}
	if pending, err := deferred.PendingJournal(manager.JournalPath()); err != nil || len(pending) != 1 {
		t.Fatalf("pending holds = %d, err = %v, want 1 after corrective outcome failure", len(pending), err)
	}
}

func assertFailedDeferredReleasePair(t *testing.T, records []receipt.Receipt, parentID string) {
	t.Helper()
	var intentID string
	for _, r := range records {
		a := r.ActionRecord
		if a.DecisionPhase == receipt.DecisionPhaseIntent && a.ParentActionID == parentID {
			if intentID != "" {
				t.Fatal("multiple intents for one released call")
			}
			intentID = a.ActionID
		}
	}
	if intentID == "" {
		t.Fatal("missing released call intent")
	}
	var outcomes int
	for _, r := range records {
		a := r.ActionRecord
		if a.DecisionPhase == receipt.DecisionPhaseOutcome && a.ActionID == intentID {
			outcomes++
			if !strings.HasPrefix(a.Pattern, "status=error ") || !strings.HasSuffix(a.Pattern, "reason="+mcpUpstreamWriteFailed) {
				t.Errorf("unexpected released call outcome: %s", a.Pattern)
			}
		}
	}
	if outcomes != 1 {
		t.Errorf("released call outcomes = %d, want 1", outcomes)
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
	blocked := make(chan BlockedRequest, 1)
	done := make(chan struct{})
	tracker := NewRequestTracker()
	go func() {
		defer close(done)
		ForwardScannedInput(transport.NewStdioReader(input), deferredReleaseFailWriter{}, io.Discard,
			config.ActionWarn, config.ActionBlock, blocked, nil, tracker, opts)
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
	records := readActionReceipts(t, h.dir)
	assertFailedDeferredReleasePair(t, records, hold.ActionID)
	var resolutions []receipt.ActionRecord
	for _, r := range records {
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
	select {
	case response := <-blocked:
		if canonicalID(response.ID) != canonicalID(ParseMCPFrame([]byte(deferKillTestCall)).ID) || response.ErrorCode == 0 {
			t.Fatalf("unexpected terminal error: %+v", response)
		}
	default:
		t.Error("client did not receive a terminal error after the held write failed")
	}
	if tracker.HasPending() {
		t.Fatal("failed write left a pending upstream response")
	}
}

func TestDeferredHTTPReleaseRecordsUpstreamSendFailure(t *testing.T) {
	attempted := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack upstream connection: %v", err)
			return
		}
		select {
		case attempted <- struct{}{}:
		default:
		}
		_ = conn.Close()
	}))
	t.Cleanup(upstream.Close)

	h := newMCPDecisionReceiptHarness(t)
	manager := newDeferKillManager(t)
	policyCfg := deferApprovalPolicy(config.DeferResolverProfile{})
	policyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
	opts := MCPProxyOpts{
		Scanner: testInputScanner(t), PolicyCfg: policyCfg, DeferManager: manager,
		ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2, RequireReceipts: true,
		PolicyHash: mcpTestPolicyHash,
	}

	ctx, cancel := context.WithCancel(t.Context())
	input, feed := io.Pipe()
	run := &httpDeferRun{stdout: &syncBuffer{}, inputW: feed, cancel: cancel, done: make(chan error, 1)}
	go func() {
		run.done <- RunHTTPProxy(ctx, input, run.stdout, io.Discard, upstream.URL, nil, opts)
	}()
	t.Cleanup(func() { run.stop(t) })

	if _, err := io.WriteString(feed, deferKillTestCall); err != nil {
		t.Fatal(err)
	}
	testwait.For(t, 5*time.Second, func() bool { return len(manager.Snapshot()) == 1 }, "deferred HTTP hold")
	hold := manager.Snapshot()[0]
	if err := manager.Resolve(hold.DeferID, config.ActionAllow, deferred.SourceApproval); err != nil {
		t.Fatal(err)
	}
	select {
	case <-attempted:
	default:
		t.Fatal("no upstream POST was attempted")
	}
	if got := run.stdout.String(); !strings.Contains(got, "upstream HTTP request failed") {
		t.Fatalf("client response = %q, want sanitized upstream error", got)
	}
	if err := h.rec.Close(); err != nil {
		t.Fatal(err)
	}

	records := readActionReceipts(t, h.dir)
	assertFailedDeferredReleasePair(t, records, hold.ActionID)
	var resolutions []receipt.ActionRecord
	for _, r := range records {
		if r.ActionRecord.DecisionPhase == receipt.DecisionPhaseResolution {
			resolutions = append(resolutions, r.ActionRecord)
		}
	}
	if len(resolutions) != 2 {
		t.Fatalf("resolution receipt count = %d, want approval and upstream send failure", len(resolutions))
	}
	approved, failed := resolutions[0], resolutions[1]
	if approved.Verdict != config.ActionAllow || failed.Verdict != config.ActionBlock ||
		failed.Pattern != "upstream_write_failed" || failed.ResolutionSource != deferred.SourceCancel ||
		failed.DeferID != hold.DeferID || failed.ParentActionID != hold.ActionID {
		t.Fatalf("approved=%+v failed=%+v", approved, failed)
	}
}
