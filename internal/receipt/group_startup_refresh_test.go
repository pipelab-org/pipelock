// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestStartupIncompleteRefreshStability(t *testing.T) {
	prepared, r, _, previous := startupPreparedWindow(t, false)
	paths, err := filepath.Glob(filepath.Join(r.Dir(), "evidence-"+previous.Shards[0].SessionID+"-*.jsonl"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("segments: %v %v", paths, err)
	}
	path := paths[len(paths)-1]
	if err = startupAppendFile(path, `{"v":`); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0o640); err != nil { // #nosec G302 -- deliberate metadata mutation in an isolated test directory.
		t.Fatal(err)
	}
	fired := false
	prepared.previous.ceremony.afterPublicationRefresh = func() {
		fired = true
		if err := startupAppendFile(path, "xyz"); err != nil {
			t.Fatal(err)
		}
	}
	err = prepared.Activate(testConfigHash)
	if !fired {
		t.Fatal("refresh seam not reached")
	}
	if !errors.Is(err, recorder.ErrEvidenceChanged) {
		t.Fatalf("unstable prefix admitted: %v", err)
	}
	for _, shard := range previous.Shards {
		if _, e := os.Stat(filepath.Join(r.Dir(), ChainLinkFileName(shard.SessionID))); !os.IsNotExist(e) {
			t.Fatalf("seal published for stale observation: %v", e)
		}
	}
	open, _ := prepared.Opening()
	n, _ := ReceiptGroupFileName(open.GroupID, "transition")
	if _, e := os.Stat(filepath.Join(r.Dir(), n)); !os.IsNotExist(e) {
		t.Fatalf("transition published for stale observation: %v", e)
	}
}

func TestStartupPublicationDirectoryPinPopulated(t *testing.T) {
	prepared, r, _, previous := startupPreparedWindow(t, true)
	c := prepared.previous.ceremony
	run := c.proofs[previous.Shards[0].SessionID].session.claim.run
	path := filepath.Join(r.Dir(), "ael", run, "recorders")
	// The pin comes from Prepare's real loader/publication path. Replacing its
	// directory with a symlink must refuse even when it exposes identical bytes.
	moved := filepath.Join(t.TempDir(), "recorders")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, path); err != nil {
		t.Fatal(err)
	}
	if err := c.checkIdentity(); !errors.Is(err, recorder.ErrEvidenceChanged) {
		t.Fatalf("real publication directory pin absent or ineffective: %v", err)
	}
}

func TestStartupCompletesPublishedTransitionAfterCancellation(t *testing.T) {
	prepared, r, _, _ := startupPreparedWindow(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	prepared.previous.ceremony.options.Context = ctx
	cancel()

	if err := prepared.Activate(testConfigHash); err != nil {
		t.Fatalf("published opening left without a transition: %v", err)
	}
	open, _ := prepared.Opening()
	name, _ := ReceiptGroupFileName(open.GroupID, "transition")
	if _, err := os.Stat(filepath.Join(r.Dir(), name)); err != nil {
		t.Fatal(err)
	}
}

func TestStartupMissingTransitionNamesRepairCommand(t *testing.T) {
	prepared, r, _, _ := startupPreparedWindow(t, true)
	open, _ := prepared.Opening()
	for _, emitter := range prepared.emitters {
		if err := emitter.AbortNativeAEL(); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := loadClosedGroupPredecessor(r.Dir(), open.GroupID, []string{open.SignerKey})
	if err == nil || !strings.Contains(err.Error(), "pipelock evidence repair-group-transition") {
		t.Fatalf("restart error = %v, want recovery command", err)
	}
	if _, err := RepairReceiptGroupTransition(r.Dir(), open.GroupID, prepared.signer, nil, verification.Options{}); err == nil {
		t.Fatal("repair signed a transition with missing successor shard openings")
	}
	name, _ := ReceiptGroupFileName(open.GroupID, "transition")
	if _, err := os.Stat(filepath.Join(r.Dir(), name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe transition was published: %v", err)
	}
}

func TestRepairReceiptGroupTransitionResumesVerifiedHistory(t *testing.T) {
	for _, closed := range []bool{true, false} {
		name := "incomplete predecessor"
		if closed {
			name = "closed predecessor"
		}
		t.Run(name, func(t *testing.T) {
			prepared, r, _, previous := startupPreparedWindow(t, closed)
			key := prepared.signer
			open, _ := prepared.Opening()
			if _, err := RepairReceiptGroupTransition(r.Dir(), open.GroupID, key, nil, verification.Options{}); err == nil || !strings.Contains(err.Error(), "stopped recorder") {
				t.Fatalf("repair with live recorder: %v", err)
			}
			for _, emitter := range prepared.emitters {
				if err := emitter.EmitSessionOpen(); err != nil {
					t.Fatal(err)
				}
				if err := emitter.AbortNativeAEL(); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			_, wrongKey := generateTestKey(t)
			if _, err := RepairReceiptGroupTransition(r.Dir(), open.GroupID, wrongKey, []string{open.SignerKey}, verification.Options{}); err == nil || !strings.Contains(err.Error(), "opening private key") {
				t.Fatalf("repair with wrong key: %v", err)
			}
			if _, err := RepairReceiptGroupTransition(r.Dir(), open.GroupID, key, nil, verification.Options{}); err != nil {
				t.Fatal(err)
			}
			trusted := []string{open.SignerKey}
			if result := VerifyReceiptGroup(r.Dir(), open.GroupID, trusted); result.Verdict != GroupIncomplete {
				t.Fatalf("repaired group verdict = %s, error=%s; want incomplete", result.Verdict, result.Error)
			}
			wantPrevious := GroupIncomplete
			if closed {
				wantPrevious = GroupValid
			}
			if result := VerifyReceiptGroup(r.Dir(), previous.GroupID, trusted); result.Verdict != wantPrevious {
				t.Fatalf("predecessor verdict = %s, error=%s; want %s", result.Verdict, result.Error, wantPrevious)
			}
			r = startupTestRecorder(t, r.Dir(), key)
			next, err := OpenSuccessorReceiptShardSet(EmitterConfig{Recorder: r, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor}, "proxy", 2, 0, open.GroupID)
			if err != nil {
				t.Fatalf("restart after repair: %v", err)
			}
			startupTestClose(t, next, r, true)
		})
	}
}
