// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestRecoverDeferredActionsPreservesShardAcrossRestart(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after int
		selected      int
		legacy        bool
		invalid       bool
		syncFailure   int
		wantError     string
	}{
		{name: "process shard", before: 2, after: 2, selected: 0},
		{name: "same layout", before: 2, after: 2, selected: 1},
		{name: "larger layout", before: 2, after: 3, selected: 1},
		{name: "smaller layout retained shard", before: 3, after: 2, selected: 1},
		{name: "smaller layout missing shard", before: 3, after: 2, selected: 2, wantError: "restore the original receipt shard configuration"},
		{name: "legacy missing selection", before: 2, after: 2, selected: 1, legacy: true, wantError: "no recorded receipt shard"},
		{name: "invalid saved index", before: 2, after: 2, selected: 1, invalid: true, wantError: "invalid saved receipt shard"},
		{name: "v1 sync failure", before: 2, after: 2, selected: 1, syncFailure: 1, wantError: "emitting deferred restart recovery receipt"},
		{name: "v2 sync failure", before: 2, after: 2, selected: 1, syncFailure: 2, wantError: "emitting deferred restart recovery receipt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, key, err := signing.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			openGroup := func(count int) (*recorder.Recorder, *mcp.MCPReceiptGroup) {
				t.Helper()
				rec, openErr := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
				if openErr != nil {
					t.Fatal(openErr)
				}
				t.Cleanup(func() { _ = rec.Close() })
				group, groupErr := buildMCPReceiptGroup(receipt.EmitterConfig{
					Recorder: rec, PrivKey: key, ConfigHash: runtimeTestPolicyHash,
					Principal: "local", Actor: "pipelock",
				}, count)
				if groupErr != nil {
					t.Fatal(groupErr)
				}
				return rec, group
			}
			closeGroup := func(rec *recorder.Recorder, group *mcp.MCPReceiptGroup) {
				t.Helper()
				for _, emitter := range group.Shards.Emitters() {
					if closeErr := emitSessionCloseAndTranscriptRoot(emitter, emitter.Session()); closeErr != nil {
						t.Fatal(closeErr)
					}
				}
				if _, closeErr := group.Shards.PublishClose(); closeErr != nil {
					t.Fatal(closeErr)
				}
				if closeErr := rec.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			rec, group := openGroup(tc.before)
			for range tc.selected {
				_ = group.Shards.Admit(receipt.EmitOpts{})
			}
			intent := group.Shards.Admit(receipt.EmitOpts{
				ActionID: "held-action", Verdict: config.ActionDefer, Transport: deferred.SurfaceMCPStdio,
				Target: "held_tool", MCPMethod: "tools/call", ToolName: "held_tool", PolicyHash: runtimeTestPolicyHash,
				DeferID: "held-defer", DecisionPhase: receipt.DecisionPhaseIntent,
			})
			if intent.ShardIndex != tc.selected || !intent.ShardSelected {
				t.Fatalf("intent selection = %+v", intent)
			}
			if _, err := mcp.EmitMCPGroupDecision(*group, nil, mcp.MCPDecision{Receipt: intent, RequireReceipt: true}); err != nil {
				t.Fatal(err)
			}
			cfg := config.Defaults()
			cfg.Defer.Enabled = true
			cfg.Defer.TimeoutSeconds = 3600 // The fixture's old process must not expire during recovery.
			cfg.FlightRecorder.Dir = filepath.Join(dir, "journal")
			if err := os.MkdirAll(cfg.FlightRecorder.Dir, 0o750); err != nil {
				t.Fatal(err)
			}
			manager := buildDeferManager(cfg, nil)
			t.Cleanup(func() { manager.ResolveAll(config.ActionBlock, deferred.SourceCancel) })
			savedIndex := intent.ShardIndex
			if tc.legacy {
				savedIndex = 0 // Both shard fields are absent, as in old journals.
			}
			if tc.invalid {
				savedIndex = -1
			}
			if err := manager.Hold(deferred.HeldAction{
				DeferID: intent.DeferID, ActionID: intent.ActionID, ShardIndex: savedIndex,
				ShardSelected: !tc.legacy, Target: intent.ToolName, Method: intent.MCPMethod,
				Surface: intent.Transport, SizeBytes: 1, Authority: deferred.AuthoritySnapshot{SessionID: "session"},
				Resolve: func(res deferred.Resolution) {
					if res.FinalDecision != config.ActionBlock || res.ResolutionSource != deferred.SourceCancel {
						t.Errorf("old process resolved unexpectedly: %+v", res)
					}
				},
			}); err != nil {
				t.Fatal(err)
			}
			wantPending := 1
			if tc.legacy || tc.invalid || tc.selected >= tc.after {
				// Even a valid, earlier-sorting hold must remain pending if
				// another hold's saved selection cannot be recovered.
				if err := manager.Hold(deferred.HeldAction{
					DeferID: "a-valid", ActionID: "valid-action", ShardSelected: true,
					Target: "held_tool", Method: "tools/call", Surface: deferred.SurfaceMCPStdio,
					SizeBytes: 1, Authority: deferred.AuthoritySnapshot{SessionID: "another-session"},
					Resolve: func(res deferred.Resolution) {
						if res.FinalDecision != config.ActionBlock || res.ResolutionSource != deferred.SourceCancel {
							t.Errorf("old process resolved unexpectedly: %+v", res)
						}
					},
				}); err != nil {
					t.Fatal(err)
				}
				wantPending++
			}
			previous, _ := group.Shards.Opening()
			closeGroup(rec, group)
			restarted, successor := openGroup(tc.after)
			opening, _ := successor.Shards.Opening()
			if opening.PreviousGroupID != previous.GroupID {
				t.Fatal("restart did not open the predecessor's successor")
			}
			var syncs int
			if tc.syncFailure != 0 {
				restarted.SetSyncForTest(func(*os.File) error {
					syncs++
					if syncs == tc.syncFailure {
						return errors.New("injected recovery sync failure")
					}
					return nil
				})
			}
			var log bytes.Buffer
			// A fresh process has no live holds. Recovery must read the journal.
			err = recoverDeferredActions(nil, manager.JournalPath(), nil, nil, successor, runtimeTestPolicyHash, &log)
			pending, journalErr := deferred.PendingJournal(manager.JournalPath())
			if journalErr != nil {
				t.Fatal(journalErr)
			}
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) || !errors.Is(err, mcp.ErrReceiptRequired) {
					t.Fatalf("recovery error = %v, want required receipt error containing %q", err, tc.wantError)
				}
				if len(pending) != wantPending {
					t.Fatalf("failed recovery left %d pending holds, want %d", len(pending), wantPending)
				}
				if tc.syncFailure != 0 && syncs < tc.syncFailure {
					t.Fatal("injected receipt sync failure was not reached")
				}
				return
			}
			if err != nil || len(pending) != 0 {
				t.Fatalf("recovery err=%v pending=%d log=%s", err, len(pending), log.String())
			}
			if err := recoverDeferredActions(nil, manager.JournalPath(), nil, nil, successor, runtimeTestPolicyHash, &log); err != nil {
				t.Fatalf("repeated recovery: %v", err)
			}
			closeGroup(restarted, successor)
			// The ordinal must survive restart, not merely produce a receipt
			// somewhere in the successor group. Both formats use that shard.
			for i, shard := range opening.Shards {
				paths, globErr := filepath.Glob(filepath.Join(dir, "evidence-"+shard.SessionID+"-*.jsonl"))
				if globErr != nil || len(paths) != 1 {
					t.Fatalf("shard evidence paths=%v error=%v", paths, globErr)
				}
				entries, readErr := recorder.ReadEntries(paths[0])
				if readErr != nil {
					t.Fatal(readErr)
				}
				var paired int
				for _, entry := range entries {
					if entry.Type == "evidence_receipt" {
						paired++
					}
				}
				want := 0
				if i == tc.selected {
					want = 1
				}
				if paired != want {
					t.Fatalf("shard %d paired receipts = %d, want %d", i, paired, want)
				}
			}
			var resolutions int
			for _, record := range readRuntimeActionRecords(t, dir) {
				if record.DecisionPhase == receipt.DecisionPhaseResolution {
					resolutions++
					if record.ParentActionID != intent.ActionID || record.DeferID != intent.DeferID || record.Verdict != config.ActionBlock || record.ResolutionSource != deferred.SourceRestartRecovery {
						t.Fatalf("unexpected recovery receipt: %+v", record)
					}
				}
			}
			if resolutions != 1 {
				t.Fatalf("resolution count = %d, want 1", resolutions)
			}
			if result := receipt.VerifyReceiptGroup(dir, opening.GroupID, []string{opening.SignerKey}); result.Verdict != receipt.GroupValid {
				t.Fatalf("successor group verification: %+v", result)
			}
		})
	}
}

// crashDuringRelease holds one call and makes the process "die" while its
// allow receipt is being written, leaving the release pending in the journal.
func crashDuringRelease(t *testing.T, dir string) *deferred.Manager {
	t.Helper()
	cfg := config.Defaults()
	cfg.Defer.Enabled = true
	cfg.FlightRecorder.Dir = dir
	manager := buildDeferManager(cfg, nil)
	if manager == nil {
		t.Fatal("buildDeferManager returned nil")
	}
	if err := manager.Hold(deferred.HeldAction{
		DeferID: "d1", ActionID: "a1", Target: "dangerous_tool",
		Surface: deferred.SurfaceMCPStdio, Method: "tools/call", Reason: "policy", SizeBytes: 1,
		Authority:    deferred.AuthoritySnapshot{SessionID: "sess", SessionIDOriginal: "sess"},
		AfterJournal: func(deferred.Resolution) error { panic("simulated crash") },
		Resolve:      func(deferred.Resolution) { t.Fatal("held call was released") },
	}); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("crash hook did not run")
			}
		}()
		_ = manager.Resolve("d1", config.ActionAllow, deferred.SourceOperator)
	}()
	return manager
}

func recoveryEmitter(t *testing.T, dir string, sync func(*os.File) error) *receipt.Emitter {
	t.Helper()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	if sync != nil {
		rec.SetSyncForTest(sync)
	}
	return receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec, PrivKey: priv, ConfigHash: "config-hash", Principal: "local", Actor: "pipelock",
	})
}

// TestRecoverDeferredActionsClosesInterruptedRelease is the restart after a
// crash between journaling a release and writing its allow receipt: recovery
// writes a block resolution receipt linked to the held call and closes the hold.
func TestRecoverDeferredActionsClosesInterruptedRelease(t *testing.T) {
	dir := t.TempDir()
	manager := crashDuringRelease(t, dir)
	if pending, err := deferred.PendingJournal(manager.JournalPath()); err != nil || len(pending) != 1 {
		t.Fatalf("pending before recovery = %d err=%v, want 1", len(pending), err)
	}

	receiptsDir := filepath.Join(dir, "receipts")
	var log bytes.Buffer
	if err := recoverDeferredActions(manager, manager.JournalPath(), recoveryEmitter(t, receiptsDir, nil), nil, nil, runtimeTestPolicyHash, &log); err != nil {
		t.Fatalf("recoverDeferredActions: %v", err)
	}
	if log.Len() != 0 {
		t.Fatalf("recovery log = %q, want empty", log.String())
	}
	if pending, err := deferred.PendingJournal(manager.JournalPath()); err != nil || len(pending) != 0 {
		t.Fatalf("pending after recovery = %d err=%v, want 0", len(pending), err)
	}
	records := readRuntimeActionRecords(t, receiptsDir)
	if len(records) != 1 {
		t.Fatalf("recovery receipts = %d, want 1", len(records))
	}
	r := records[0]
	if r.Verdict != config.ActionBlock || r.DecisionPhase != receipt.DecisionPhaseResolution ||
		r.ResolutionSource != deferred.SourceRestartRecovery || r.ParentActionID != "a1" || r.PolicyHash != runtimeTestPolicyHash {
		t.Fatalf("recovery receipt = %+v, want block restart_recovery resolution of a1", r)
	}
}

// TestRecoverDeferredActionsKeepsHoldWhenReceiptNotDurable checks the recovery
// receipt is synced before the journal closes the hold. If it cannot be synced,
// recovery fails and the hold stays pending for the next start, rather than a
// closed hold whose only receipt could still be lost.
func TestRecoverDeferredActionsKeepsHoldWhenReceiptNotDurable(t *testing.T) {
	dir := t.TempDir()
	manager := crashDuringRelease(t, dir)
	emitter := recoveryEmitter(t, filepath.Join(dir, "receipts"), func(*os.File) error {
		return errors.New("injected sync failure")
	})
	var log bytes.Buffer
	err := recoverDeferredActions(manager, manager.JournalPath(), emitter, nil, nil, runtimeTestPolicyHash, &log)
	if err == nil {
		t.Fatal("recoverDeferredActions succeeded with an unsynced recovery receipt")
	}
	if pending, err := deferred.PendingJournal(manager.JournalPath()); err != nil || len(pending) != 1 {
		t.Fatalf("pending after failed recovery = %d err=%v, want the hold still pending", len(pending), err)
	}
}
