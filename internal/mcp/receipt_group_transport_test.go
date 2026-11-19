// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestDeferredResolutionKeepsAdmissionShard(t *testing.T) {
	opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
	set := opts.ReceiptGroup.Shards
	_ = set.Admit(receipt.EmitOpts{})
	intent := set.Admit(receipt.EmitOpts{
		ActionID: "deferred-shard-action", Verdict: config.ActionDefer,
		Transport: opts.Transport, Target: "tools/call", PolicyHash: mcpTestPolicyHash,
	})
	if intent.ShardIndex != 1 {
		t.Fatalf("admission shard = %d, want 1", intent.ShardIndex)
	}
	if _, err := opts.emitReceiptDecision(MCPDecision{Receipt: intent, RequireReceipt: true}); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	if err := EmitDeferredResolutionReceipt(opts, &log, deferred.Resolution{
		DeferID: intent.ActionID, ParentActionID: intent.ActionID,
		ShardIndex: intent.ShardIndex, ShardSelected: intent.ShardSelected,
		FinalDecision: config.ActionBlock, ResolutionSource: deferred.SourceOperator,
		Target: "tools/call", Method: "tools/call",
	}); err != nil {
		t.Fatal(err)
	}
	for _, emitter := range set.Emitters() {
		if err := emitter.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := emitter.EmitTranscriptRoot(emitter.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := set.PublishClose(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	assertMCPTransportReceiptShard(t, dir, shards, intent.ActionID, 0)
	open, _ := set.Opening()
	if got := receipt.VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey}); got.Verdict != receipt.GroupValid {
		t.Fatalf("group verdict = %+v", got)
	}
}

func newMCPTransportReceiptGroup(t *testing.T) (MCPProxyOpts, *recorder.Recorder, string, []receipt.ReceiptGroupShard) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	shards, err := receipt.OpenInitialReceiptShardSet(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: mcpTestPolicyHash,
		Principal: "local", Actor: "pipelock",
	}, "proxy", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	opening, _ := shards.Opening()
	group := &MCPReceiptGroup{Shards: shards, V2: make([]*proxydecision.Emitter, 2)}
	for i, shard := range opening.Shards {
		group.V2[i] = proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder: rec, Signer: proxydecision.NewKeyedSigner(key),
			Principal: "local", Actor: "pipelock", Session: shard.SessionID,
		})
	}
	return MCPProxyOpts{
		ReceiptGroup: group, ReceiptEmitter: shards.ProcessEmitter(), V2ReceiptEmitter: group.V2[0],
		RequireReceipts: true, PolicyHash: mcpTestPolicyHash, Transport: "mcp_http_listener",
		AuthorityDestination: "https://mcp.vendor.example",
	}, rec, dir, opening.Shards
}

func assertMCPTransportReceiptShard(t *testing.T, dir string, shards []receipt.ReceiptGroupShard, actionID string, wantOtherV2 int) {
	t.Helper()
	for i, shard := range shards {
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("shard %d evidence files=%v err=%v", i, paths, err)
		}
		entries, err := recorder.ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		var v1, v2 int
		for _, entry := range entries {
			if entry.Type == "action_receipt" && bytes.Contains(entry.RawDetail, []byte(actionID)) {
				v1++
			}
			if entry.Type == "evidence_receipt" {
				v2++
			}
		}
		if i == 1 {
			if v1 != 2 || v2 != 2 {
				t.Fatalf("shard %d action %s: v1=%d v2=%d, want paired decision and outcome", i, actionID, v1, v2)
			}
		} else if v1 != 0 || v2 != wantOtherV2 {
			t.Fatalf("other shard %d: v1=%d v2=%d, want 0 and %d", i, v1, v2, wantOtherV2)
		}
	}
}

func TestListenerStreamErrorSettlesOpenIntentOnce(t *testing.T) {
	opts, rec, dir, _ := newMCPTransportReceiptGroup(t)
	_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
	var outcome TrackedRequestOutcome
	intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
		ActionID: "listener-stream-end", Verdict: config.ActionAllow,
		Transport: opts.Transport, Target: "initialize", Method: "initialize",
		PolicyHash: mcpTestPolicyHash,
	})
	if _, err := opts.emitReceiptDecision(MCPDecision{
		Receipt: intent, outcome: &outcome, RequireReceipt: true, RequiredMode: true,
	}); err != nil {
		t.Fatal(err)
	}
	if outcome.handle == nil || outcome.Receipt.ActionID != intent.ActionID {
		t.Fatal("confirmed intent did not grant one settlement handle")
	}
	var log bytes.Buffer
	// A stream that fails after bytes were written records one outcome. The
	// listener's request-end settlement must not append a second one.
	recordListenerStreamError(context.Background(), &log, opts, outcome, false, transport.ErrIncompleteResponse)
	outcome.settle(&log, opts, "incomplete", -1, "listener_request_ended")
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	var outcomes int
	var patterns []string
	for _, rcpt := range readDirActionReceipts(t, dir) {
		if rcpt.ActionRecord.ActionID != intent.ActionID || rcpt.ActionRecord.DecisionPhase != receipt.DecisionPhaseOutcome {
			continue
		}
		outcomes++
		patterns = append(patterns, rcpt.ActionRecord.Pattern)
	}
	if outcomes != 1 || len(patterns) != 1 || patterns[0] != "status=200 bytes=unknown reason=incomplete" {
		t.Fatalf("outcome receipts = %d (%q), want the stream failure alone", outcomes, patterns)
	}
}

func readDirActionReceipts(t *testing.T, dir string) []receipt.Receipt {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var receipts []receipt.Receipt
	for _, path := range paths {
		entries, err := recorder.ReadEntries(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Type != actionReceiptEntryType {
				continue
			}
			detailJSON, err := json.Marshal(entry.Detail)
			if err != nil {
				t.Fatal(err)
			}
			rcpt, err := receipt.Unmarshal(detailJSON)
			if err != nil {
				t.Fatal(err)
			}
			receipts = append(receipts, rcpt)
		}
	}
	return receipts
}

func TestMCPStreamOutcomesKeepAdmissionShard(t *testing.T) {
	for _, path := range []string{"listener", "tracked_upstream"} {
		t.Run(path, func(t *testing.T) {
			opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
			// Admission must choose the non-process shard; a process-emitter
			// fallback would then be visible in the evidence files.
			_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
			intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
				ActionID: "stream-shard-action", Verdict: config.ActionAllow,
				Transport: opts.Transport, Target: "initialize", PolicyHash: mcpTestPolicyHash,
			})
			if intent.ShardIndex != 1 {
				t.Fatalf("admission shard = %d, want 1", intent.ShardIndex)
			}
			if _, err := opts.emitReceiptDecision(MCPDecision{Receipt: intent, RequireReceipt: true}); err != nil {
				t.Fatal(err)
			}
			var log bytes.Buffer
			switch path {
			case "listener":
				recordListenerStreamError(context.Background(), &log, opts, TrackedRequestOutcome{Receipt: intent}, false, transport.ErrIncompleteResponse)
			case "tracked_upstream":
				tracker := NewRequestTracker()
				tracker.TrackOutcome(json.RawMessage(`1`), TrackedRequestOutcome{Receipt: intent})
				emitTrackedStreamError(context.Background(), &log, tracker, json.RawMessage(`1`), opts, transport.ErrIncompleteResponse)
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			assertMCPTransportReceiptShard(t, dir, shards, intent.ActionID, 0)
		})
	}
}

func TestMCPContractRefusalKeepsAdmissionShard(t *testing.T) {
	opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
	_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
	intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
		ActionID: "refused-shard-action", Verdict: config.ActionAllow,
		Transport: opts.Transport, Target: "fetch", MCPMethod: methodToolsCall,
		ToolName: "fetch", PolicyHash: mcpTestPolicyHash,
	})
	if intent.ShardIndex != 1 {
		t.Fatalf("admission shard = %d, want 1", intent.ShardIndex)
	}
	if _, err := opts.emitReceiptDecision(MCPDecision{Receipt: intent}); err != nil {
		t.Fatal(err)
	}
	emitContractRefusedOutcome(io.Discard, TrackedRequestOutcome{Receipt: intent}, mcpContractGateOutput{}, "contract_refused", 0, opts)
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	assertMCPTransportReceiptShard(t, dir, shards, intent.ActionID, 0)
}

func TestMCPStreamRequiredOutcomeFailureClasses(t *testing.T) {
	for _, tc := range []struct {
		name       string
		breakShard func(*MCPReceiptGroup, *recorder.Recorder)
		wantStop   bool
	}{
		{"missing_v2_pair", func(g *MCPReceiptGroup, _ *recorder.Recorder) { g.V2[1] = nil }, false},
		{"unhealthy_v1", func(g *MCPReceiptGroup, _ *recorder.Recorder) {
			g.Shards.Emitters()[1].MarkUnhealthy(errors.New("writer failed"))
		}, true},
		{"post_advance_sync_failure", func(_ *MCPReceiptGroup, rec *recorder.Recorder) {
			rec.SetSyncForTest(func(*os.File) error { return errors.New("sync failed") })
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, rec, _, _ := newMCPTransportReceiptGroup(t)
			_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
			intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
				ActionID: "stream-failure", Verdict: config.ActionAllow,
				Transport: opts.Transport, Target: "initialize", PolicyHash: mcpTestPolicyHash,
			})
			var stops int
			opts.ReceiptGroup.OnRequiredFailure = func(error) { stops++ }
			tc.breakShard(opts.ReceiptGroup, rec)
			var log bytes.Buffer
			recordListenerStreamError(context.Background(), &log, opts, TrackedRequestOutcome{Receipt: intent}, false, io.ErrUnexpectedEOF)
			if !bytes.Contains(log.Bytes(), []byte("receipt")) {
				t.Fatalf("required outcome failure was not logged: %q", log.String())
			}
			if (stops != 0) != tc.wantStop {
				t.Fatalf("required failure callback count=%d, want stop=%t", stops, tc.wantStop)
			}
			if unhealthy := opts.ReceiptGroup.Shards.Emitters()[0].HealthError() != nil; unhealthy != tc.wantStop {
				t.Fatalf("other shard unhealthy=%t, want %t", unhealthy, tc.wantStop)
			}
		})
	}
}

func TestMCPBestEffortStreamOutcomeFailureKeepsGroupRunning(t *testing.T) {
	for _, path := range []string{"stream", "websocket", "sse", "outcome"} {
		t.Run(path, func(t *testing.T) {
			opts, rec, _, _ := newMCPTransportReceiptGroup(t)
			opts.RequireReceipts = false
			_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
			var stops int
			opts.ReceiptGroup.OnRequiredFailure = func(error) { stops++ }
			// A failed v2 pair is pre-advance: no shard may be quarantined.
			opts.ReceiptGroup.V2[1] = nil
			var log bytes.Buffer
			switch path {
			case "stream":
				intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
					ActionID: "stream-best-effort", Verdict: config.ActionAllow,
					Transport: opts.Transport, Target: "initialize", PolicyHash: mcpTestPolicyHash,
				})
				recordListenerStreamError(context.Background(), &log, opts, TrackedRequestOutcome{Receipt: intent}, false, io.ErrUnexpectedEOF)
			case "outcome":
				intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
					ActionID: "outcome-best-effort", Verdict: config.ActionAllow,
					Transport: opts.Transport, Target: "initialize", PolicyHash: mcpTestPolicyHash,
				})
				emitMCPOutcomeReceipt(nil, nil, opts.ReceiptGroup, &log, intent, "incomplete", -1, "stream_closed", opts.requireReceipts())
			case "websocket":
				emitMCPStandaloneStreamReceipt(opts, &log, mcpStreamReceipt(opts, "WS"), "incomplete", httpstream.Incomplete)
			case "sse":
				emitMCPStandaloneStreamReceipt(opts, &log, mcpStreamReceipt(opts, http.MethodGet), "incomplete", httpstream.Incomplete)
			}
			if stops != 0 || !bytes.Contains(log.Bytes(), []byte("receipt")) {
				t.Fatalf("best-effort outcome stops=%d log=%q", stops, log.String())
			}
			for i, shard := range opts.ReceiptGroup.Shards.Emitters() {
				if err := shard.HealthError(); err != nil {
					t.Fatalf("shard %d quarantined after pre-advance failure: %v", i, err)
				}
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMCPGroupedDeferAndRefusalFailureModes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required bool
		deferRun bool
	}{
		{"best_effort_defer", false, true},
		{"required_defer", true, true},
		{"best_effort_refusal", false, false},
		{"required_refusal", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, rec, _, _ := newMCPTransportReceiptGroup(t)
			opts.RequireReceipts = tc.required
			_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
			shard := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
				ActionID: "failure-mode", Transport: opts.Transport,
				Target: "fetch", MCPMethod: methodToolsCall, ToolName: "fetch",
				PolicyHash: mcpTestPolicyHash,
			})
			if shard.ShardIndex != 1 {
				t.Fatalf("admission shard = %d, want 1", shard.ShardIndex)
			}
			var stops int
			opts.ReceiptGroup.OnRequiredFailure = func(error) { stops++ }
			var log bytes.Buffer
			if tc.deferRun {
				rec.SetSyncForTest(func(*os.File) error { return errors.New("sync failed") })
				err := emitMCPToolReceipt(mcpToolReceiptOpts{
					ProxyOpts: opts,
					Shard:     shard, Log: &log,
					ActionID: shard.ActionID, Transport: opts.Transport,
					ToolName: "fetch", Verdict: config.ActionAllow,
					DecisionPhase:  receipt.DecisionPhaseResolution,
					RequireReceipt: true, RequireReceipts: tc.required, Durable: true,
				})
				if !errors.Is(err, ErrReceiptRequired) {
					t.Fatalf("defer emit error = %v, want required call failure", err)
				}
			} else {
				opts.ReceiptGroup.Shards.Emitters()[1].MarkUnhealthy(errors.New("writer failed"))
				emitMCPBlockedOutcomeReceipt(nil, nil, opts.ReceiptGroup, &log, shard, 0, "contract_refused", tc.required)
				if !strings.Contains(log.String(), "receipt") {
					t.Fatalf("refused outcome failure not logged: %q", log.String())
				}
			}
			if tc.required {
				if stops != 1 || opts.ReceiptGroup.Shards.Emitters()[0].HealthError() == nil {
					t.Fatalf("required failure stops=%d other shard health=%v", stops, opts.ReceiptGroup.Shards.Emitters()[0].HealthError())
				}
			} else if stops != 0 || opts.ReceiptGroup.Shards.Emitters()[0].HealthError() != nil {
				t.Fatalf("best-effort failure stops=%d other shard health=%v", stops, opts.ReceiptGroup.Shards.Emitters()[0].HealthError())
			}
		})
	}
}

func TestMCPStreamReceiptSingleChainFieldsUnchanged(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, "WS"} {
		t.Run(method, func(t *testing.T) {
			opts := MCPProxyOpts{Transport: "mcp_http_upstream", AuthorityDestination: "https://mcp.vendor.example", PolicyHash: mcpTestPolicyHash}
			got := mcpStreamReceipt(opts, method)
			if got.ActionID == "" || got.Transport != opts.Transport || got.Method != method || got.Target != opts.AuthorityDestination || got.PolicyHash != opts.PolicyHash || got.ShardSelected {
				t.Fatalf("single-chain stream receipt changed: %+v", got)
			}
		})
	}
}

func TestMCPStandaloneStreamSingleChainOutcomeUnchanged(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, "WS"} {
		t.Run(method, func(t *testing.T) {
			h := newMCPDecisionReceiptHarness(t)
			opts := MCPProxyOpts{
				ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2,
				Transport: "mcp_http_upstream", AuthorityDestination: "https://mcp.vendor.example",
				PolicyHash: mcpTestPolicyHash,
			}
			intent := mcpStreamReceipt(opts, method)
			emitMCPStandaloneStreamReceipt(opts, io.Discard, intent, "incomplete", httpstream.Incomplete)
			if err := h.rec.Close(); err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, entry := range readReceiptEntriesHTTP(t, h.dir) {
				if entry.Type != "action_receipt" || !bytes.Contains(entry.RawDetail, []byte(intent.ActionID)) {
					continue
				}
				found = true
				if !bytes.Contains(entry.RawDetail, []byte(`"decision_phase":"outcome"`)) || !bytes.Contains(entry.RawDetail, []byte(`"verdict":"allow"`)) || bytes.Contains(entry.RawDetail, []byte(`"shard_index"`)) {
					t.Fatalf("single-chain %s receipt fields changed: %s", method, entry.RawDetail)
				}
			}
			if !found {
				t.Fatal("missing single-chain outcome receipt")
			}
		})
	}
}

func TestMCPStandaloneStreamRequiredFailureClasses(t *testing.T) {
	for _, method := range []string{http.MethodGet, "WS"} {
		t.Run(method, func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				breakShard func(*MCPReceiptGroup, *recorder.Recorder)
				wantStop   bool
			}{
				{"missing_v2_pair", func(g *MCPReceiptGroup, _ *recorder.Recorder) { g.V2[1] = nil }, false},
				{"unhealthy_v1", func(g *MCPReceiptGroup, _ *recorder.Recorder) {
					g.Shards.Emitters()[1].MarkUnhealthy(errors.New("writer failed"))
				}, true},
				{"post_advance_sync_failure", func(_ *MCPReceiptGroup, rec *recorder.Recorder) {
					rec.SetSyncForTest(func(*os.File) error { return errors.New("sync failed") })
				}, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					opts, rec, _, _ := newMCPTransportReceiptGroup(t)
					_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
					var stops int
					opts.ReceiptGroup.OnRequiredFailure = func(error) { stops++ }
					tc.breakShard(opts.ReceiptGroup, rec)
					var log bytes.Buffer
					emitMCPStandaloneStreamReceipt(opts, &log, mcpStreamReceipt(opts, method), "incomplete", httpstream.Incomplete)
					if !bytes.Contains(log.Bytes(), []byte("receipt")) {
						t.Fatalf("required diagnostic failure was not logged: %q", log.String())
					}
					if (stops != 0) != tc.wantStop {
						t.Fatalf("required failure callback count=%d, want stop=%t", stops, tc.wantStop)
					}
					if unhealthy := opts.ReceiptGroup.Shards.Emitters()[0].HealthError() != nil; unhealthy != tc.wantStop {
						t.Fatalf("other shard unhealthy=%t, want %t", unhealthy, tc.wantStop)
					}
				})
			}
		})
	}
}

func TestMCPWebSocketOutcomeKeepsAdmissionShard(t *testing.T) {
	responseSent := make(chan struct{})
	srv := wsRespondServer(t, []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`), responseSent)
	defer srv.Close()
	opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
	opts.Scanner = testScannerForWS(t)
	stdin, input := io.Pipe()
	defer func() { _ = input.Close() }()
	var stdout, stderr lockedHTTPBuffer
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunWSProxy(ctx, struct{ io.Reader }{stdin}, &stdout, &stderr, wsURL(srv), opts) }()
	_, _ = io.WriteString(input, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`+"\n")
	waitForResponse(t, responseSent)
	testwait.For(t, time.Second, func() bool { return stdout.contains(`"id":1`) }, "WebSocket response forwarded")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	// The upgrade takes the first shard and initialize takes the next.
	records := make(map[string][]receipt.ActionRecord)
	for _, entry := range readReceiptEntriesHTTP(t, dir) {
		if entry.Type != actionReceiptEntryType {
			continue
		}
		signed, err := receipt.Unmarshal(entry.RawDetail)
		if err != nil {
			t.Fatal(err)
		}
		if signed.ActionRecord.SessionControl != nil {
			continue
		}
		records[entry.SessionID] = append(records[entry.SessionID], signed.ActionRecord)
	}
	upgrade, initialize := records[shards[0].SessionID], records[shards[1].SessionID]
	if len(records) != 2 || len(upgrade) != 2 || len(initialize) != 2 {
		t.Fatalf("want upgrade and initialize pairs on separate shards, got %v", records)
	}
	assertMCPTransportReceiptPair(t, upgrade[0], upgrade[1], receipt.ActionRecord{
		Method: settlementUpgrade, Transport: "mcp_ws", Target: wsURL(srv),
		Verdict: config.ActionForward, Pattern: completedMCPStreamPattern,
	})
	assertMCPWebSocketInitializePair(t, initialize[0], initialize[1], upgrade[0].ActionID)
	assertMCPTransportReceiptShard(t, dir, shards, initialize[0].ActionID, 2)
}

const completedMCPStreamPattern = "status=completed bytes=unknown reason=stream_completed"

func assertMCPTransportReceiptPair(t *testing.T, admission, terminal receipt.ActionRecord, want receipt.ActionRecord) {
	t.Helper()
	if admission.ActionID == "" || admission.Layer != mcpTransportAdmissionLayer || admission.DecisionPhase != "" ||
		admission.Method != want.Method || admission.Transport != want.Transport || admission.Target != want.Target || admission.Verdict != config.ActionForward {
		t.Fatalf("transport admission = %+v", admission)
	}
	if terminal.ActionID != admission.ActionID || terminal.Layer != mcpOutcomeLayer || terminal.DecisionPhase != "" ||
		terminal.Method != want.Method || terminal.Transport != want.Transport || terminal.Target != want.Target ||
		terminal.Verdict != want.Verdict || terminal.Pattern != want.Pattern {
		t.Fatalf("transport terminal = %+v, want %s with pattern %q for %s", terminal, want.Verdict, want.Pattern, admission.ActionID)
	}
}

func TestRequiredBridgeGETAdmitsBeforeOpen(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		reason string
	}{
		{name: "completed", status: http.StatusOK, reason: "stream_completed"},
		{name: "unsupported", status: http.StatusMethodNotAllowed, reason: "upstream_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, rec, dir, _ := newMCPTransportReceiptGroup(t)
			opts.Scanner = testScannerForHTTP(t)
			opts.Transport = "mcp_http_upstream"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					http.NotFound(w, r)
					return
				}
				if !bridgeGETReceiptRecorded(t, dir, `"layer":"mcp_transport_admission"`, `"verdict":"forward"`) {
					t.Error("upstream GET opened before its transport admission was recorded")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			opts.AuthorityDestination = srv.URL
			ctx, cancel := context.WithCancel(t.Context())
			var wg sync.WaitGroup
			t.Cleanup(func() {
				cancel()
				wg.Wait()
			})
			var stderr lockedHTTPBuffer
			startGETStream(ctx, transport.NewHTTPClient(srv.URL, nil), &syncWriter{w: io.Discard}, &syncWriter{w: &stderr}, opts, NewRequestTracker(), &wg)
			testwait.For(t, 3*time.Second, func() bool {
				return bridgeGETReceiptRecorded(t, dir, `"layer":"`+mcpOutcomeLayer+`"`, "reason="+tc.reason)
			}, "required GET result recorded")
			cancel()
			wg.Wait()
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRequiredBridgeGETStaysClosedWhenAdmissionFails(t *testing.T) {
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	opts, rec, _, _ := newMCPTransportReceiptGroup(t)
	opts.Scanner = testScannerForHTTP(t)
	opts.Transport = "mcp_http_upstream"
	opts.AuthorityDestination = srv.URL
	rec.SetReceiptAppendGuardForTest(func(recorder.Entry) error {
		return errors.New("injected admission failure")
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var wg sync.WaitGroup
	var stderr lockedHTTPBuffer
	startGETStream(ctx, transport.NewHTTPClient(srv.URL, nil), &syncWriter{w: io.Discard}, &syncWriter{w: &stderr}, opts, NewRequestTracker(), &wg)
	testwait.For(t, 3*time.Second, func() bool {
		return strings.Count(stderr.String(), "receipt emission failed") >= 2
	}, "admission refusal and retry")
	cancel()
	wg.Wait()
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if gets.Load() != 0 {
		t.Fatalf("upstream GETs = %d, want 0 when the transport admission cannot be recorded", gets.Load())
	}
}

func bridgeGETReceiptRecorded(t *testing.T, dir, layer, detail string) bool {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
	if err != nil {
		t.Error(err)
		return false
	}
	for _, path := range paths {
		entries, err := recorder.ReadEntries(path)
		if err != nil {
			t.Error(err)
			return false
		}
		for _, entry := range entries {
			if entry.Type == "action_receipt" &&
				bytes.Contains(entry.RawDetail, []byte(layer)) &&
				bytes.Contains(entry.RawDetail, []byte(`"method":"GET"`)) &&
				bytes.Contains(entry.RawDetail, []byte(detail)) {
				return true
			}
		}
	}
	return false
}

func TestMCPGETSSEIncompleteOutcomeUsesSelectedShard(t *testing.T) {
	const notification = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\"}\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", "4096")
		_, _ = io.WriteString(w, notification)
	}))
	defer srv.Close()
	opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
	opts.Scanner = testScannerForHTTP(t)
	opts.Transport = "mcp_http_upstream"
	opts.AuthorityDestination = srv.URL
	_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
	var stderr lockedHTTPBuffer
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	startGETStream(ctx, transport.NewHTTPClient(srv.URL, nil), &syncWriter{w: io.Discard}, &syncWriter{w: &stderr}, opts, NewRequestTracker(), &wg)
	testwait.For(t, 3*time.Second, func() bool { return stderr.contains("GET stream scan error") }, "incomplete GET SSE outcome")
	cancel()
	wg.Wait()
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	assertMCPStandaloneDiagnosticShard(t, dir, shards, 1, 2)
}

func TestMCPWebSocketStandaloneFailureUsesSelectedShard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			t.Errorf("WebSocket upgrade: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		// A declared five-byte text frame with one byte of payload is a
		// transport failure with no admitted JSON-RPC request.
		_, _ = conn.Write([]byte{0x81, 0x05, 'x'})
	}))
	defer srv.Close()
	opts, rec, dir, shards := newMCPTransportReceiptGroup(t)
	opts.Scanner = testScannerForWS(t)
	_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
	stdin, input := io.Pipe()
	defer func() { _ = input.Close() }()
	var stdout, stderr lockedHTTPBuffer
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := RunWSProxy(ctx, stdin, &stdout, &stderr, wsURL(srv), opts); err != nil && !strings.Contains(err.Error(), "incomplete") {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	assertMCPStandaloneDiagnosticShard(t, dir, shards, 1, 2)
}

func assertMCPStandaloneDiagnosticShard(t *testing.T, dir string, shards []receipt.ReceiptGroupShard, selected, wantV2 int) {
	t.Helper()
	for i, shard := range shards {
		paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("shard %d evidence files=%v err=%v", i, paths, err)
		}
		entries, err := recorder.ReadEntries(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		var diagnostic, admission, v2 int
		for _, entry := range entries {
			if entry.Type == "action_receipt" && bytes.Contains(entry.RawDetail, []byte("reason=incomplete")) {
				if bytes.Contains(entry.RawDetail, []byte(`"decision_phase":`)) || !bytes.Contains(entry.RawDetail, []byte(`"verdict":"warn"`)) {
					t.Fatal("standalone stream diagnostic claimed a decision phase or success verdict")
				}
				diagnostic++
			}
			if entry.Type == "action_receipt" && bytes.Contains(entry.RawDetail, []byte(`"layer":"mcp_transport_admission"`)) {
				admission++
			}
			if entry.Type == "evidence_receipt" {
				v2++
			}
		}
		if i == selected && (diagnostic != 1 || v2 != wantV2 || (wantV2 > 1 && admission != 1) || (wantV2 == 1 && admission != 0)) {
			t.Fatalf("selected shard %d: diagnostic=%d admission=%d v2=%d, want 1 and v2=%d", i, diagnostic, admission, v2, wantV2)
		}
		if i != selected && (diagnostic != 0 || v2 != 0 || admission != 0) {
			t.Fatalf("other shard %d: diagnostic=%d admission=%d v2=%d, want 0/0/0", i, diagnostic, admission, v2)
		}
	}
}

func TestBlockedOutcomeClaimAfterFailedAppend(t *testing.T) {
	for _, afterAdvance := range []bool{false, true} {
		name := "before advance"
		if afterAdvance {
			name = "after advance"
		}
		t.Run(name, func(t *testing.T) {
			opts, rec, _, _ := newMCPTransportReceiptGroup(t)
			intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
				ActionID: "blocked-action", Verdict: config.ActionAllow, Method: methodToolsCall,
				Transport: opts.Transport, Target: "tool:lookup", PolicyHash: mcpTestPolicyHash,
			})
			var outcome TrackedRequestOutcome
			if _, err := opts.emitAdmittedReceiptDecision(MCPDecision{
				Receipt: intent, RequireReceipt: true, RequiredMode: true, outcome: &outcome,
			}); err != nil {
				t.Fatal(err)
			}
			if outcome.handle == nil {
				t.Fatal("required intent has no outcome handle")
			}
			if !outcome.handle.settled.CompareAndSwap(false, true) {
				t.Fatal("outcome already claimed")
			}
			failure := errors.New("blocked receipt write failed")
			if afterAdvance {
				rec.SetSyncForTest(func(*os.File) error { return failure })
			} else {
				rec.SetReceiptAppendGuardForTest(func(recorder.Entry) error { return failure })
			}
			blocked := mcpOutcomeReceiptOpts(outcome.Receipt, mcpOutcomeStatusBlocked, -1, "inspection refused")
			blocked.Verdict = config.ActionBlock
			blocked.Layer = "inspection"
			err := outcome.handle.emit(io.Discard, blocked, true)
			want := receipt.ErrReceiptNotAppended
			if afterAdvance {
				want = receipt.ErrReceiptPostAdvance
			}
			if !errors.Is(err, want) {
				t.Fatalf("blocked append error = %v, want %v", err, want)
			}
			rec.SetReceiptAppendGuardForTest(nil)
			settled, err := outcome.settleResult(io.Discard, opts, mcpOutcomeStatusBlocked, -1, "inspection refused")
			if settled == afterAdvance || err != nil {
				t.Fatalf("settlement = %t, %v, want %t, nil", settled, err, !afterAdvance)
			}
		})
	}
}

func TestRequiredOutcomeV2FailureKeepsV1Claim(t *testing.T) {
	opts, rec, dir, _ := newMCPTransportReceiptGroup(t)
	_ = opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{})
	intent := opts.ReceiptGroup.Shards.Admit(receipt.EmitOpts{
		ActionID: "v2-outcome-refused", Verdict: config.ActionAllow, Method: methodToolsCall,
		Transport: opts.Transport, Target: "tool:lookup", PolicyHash: mcpTestPolicyHash,
	})
	var groupFailure error
	opts.ReceiptGroup.OnRequiredFailure = func(err error) { groupFailure = err }
	var outcome TrackedRequestOutcome
	if _, err := opts.emitAdmittedReceiptDecision(MCPDecision{
		Receipt: intent, RequireReceipt: true, RequiredMode: true, outcome: &outcome,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := opts.ReceiptGroup.V2[intent.ShardIndex].Retire(); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	settled, err := outcome.settleResult(&log, opts, "error", -1, "upstream_error")
	if settled || !errors.Is(err, errMCPV2ReceiptEmit) || !errors.Is(groupFailure, errMCPV2ReceiptEmit) {
		t.Fatalf("first settlement = %t, %v, group failure = %v", settled, err, groupFailure)
	}
	if settled, err := outcome.settleResult(&log, opts, "error", -1, "upstream_error"); settled || err != nil {
		t.Fatalf("retry after v1 append = %t, %v", settled, err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	open, _ := opts.ReceiptGroup.Shards.Opening()
	shard := open.Shards[intent.ShardIndex]
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("shard evidence files = %v, error = %v", paths, err)
	}
	entries, err := recorder.ReadEntries(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var v1Outcomes, v2 int
	for _, entry := range entries {
		if entry.Type == actionReceiptEntryType && bytes.Contains(entry.RawDetail, []byte(intent.ActionID)) &&
			bytes.Contains(entry.RawDetail, []byte(`"decision_phase":"outcome"`)) {
			v1Outcomes++
		}
		if entry.Type == "evidence_receipt" {
			v2++
		}
	}
	if v1Outcomes != 1 || v2 != 1 {
		t.Fatalf("selected shard contains %d v1 outcomes and %d v2 receipts, want one of each", v1Outcomes, v2)
	}
}

func TestRequiredTransportResultReportsAppendRefusal(t *testing.T) {
	opts, rec, _, _ := newMCPTransportReceiptGroup(t)
	admission, err := admitDurableTransport(opts, http.MethodGet, opts.AuthorityDestination)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("transport result append refused")
	rec.SetReceiptAppendGuardForTest(func(recorder.Entry) error { return injected })
	var log bytes.Buffer
	recordTransportAdmissionResult(&log, opts, admission, "completed", "stream_completed")
	if !strings.Contains(log.String(), injected.Error()) {
		t.Fatalf("required transport result log = %q, want %q", log.String(), injected)
	}
}
