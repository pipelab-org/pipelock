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
			if _, err := RepairReceiptGroupTransition(r.Dir(), open.GroupID, key, nil, verification.Options{}); err == nil || err.Error() != "receipt group transition already exists" {
				t.Fatalf("repeat repair error = %v, want existing transition refusal", err)
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

func TestRepairReceiptGroupTransitionRefusesEarlierGroup(t *testing.T) {
	prepared, r, _, previous := startupPreparedWindow(t, true)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := RepairReceiptGroupTransition(r.Dir(), previous.GroupID, prepared.signer, nil, verification.Options{})
	const want = "transition repair requires the terminal receipt group"
	if err == nil || err.Error() != want {
		t.Fatalf("repair error = %v, want %q", err, want)
	}
}

func TestRepairReceiptGroupTransitionRefusesMissingPredecessor(t *testing.T) {
	prepared, r, _, previous := startupPreparedWindow(t, true)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	name, err := ReceiptGroupFileName(previous.GroupID, "open")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(r.Dir(), name)); err != nil {
		t.Fatal(err)
	}
	open, _ := prepared.Opening()
	_, err = RepairReceiptGroupTransition(r.Dir(), open.GroupID, prepared.signer, nil, verification.Options{})
	if err == nil || err.Error() != "receipt group history has more than one terminal group" {
		t.Fatalf("repair error = %v, want missing predecessor", err)
	}
}

func TestPublishedGroupWalkOptionsKeepsProofErrors(t *testing.T) {
	proofErr := errors.New("proof read failed")
	for _, tc := range []struct {
		err  error
		want error
	}{
		{err: context.Canceled},
		{err: context.DeadlineExceeded},
		{err: proofErr, want: proofErr},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			var progress verification.Progress
			ceremony := startupGroupVerification{
				published: true,
				options: verification.Options{Context: ctx, Progress: func(got verification.Progress) error {
					progress = got
					return tc.err
				}},
			}
			expected := verification.Progress{Kind: "records", Records: 1}
			if err := ceremony.walkOptions().Report(expected); !errors.Is(err, tc.want) || progress != expected {
				t.Fatalf("progress = %+v, error = %v, want %+v, %v", progress, err, expected, tc.want)
			}
		})
	}
}

func TestRepairReceiptGroupTransitionRejectsInvalidInputs(t *testing.T) {
	dir := t.TempDir()
	_, key := generateTestKey(t)
	const validID = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name    string
		groupID string
		key     []byte
		want    string
	}{
		{name: "signing key", groupID: validID, want: "receipt group requires a signing key"},
		{name: "group ID", groupID: "invalid", key: key, want: "invalid receipt group ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RepairReceiptGroupTransition(dir, tc.groupID, tc.key, nil, verification.Options{}); err == nil || err.Error() != tc.want {
				t.Fatalf("repair error = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := RepairReceiptGroupTransition(dir, validID, key, nil, verification.Options{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing opening error = %v, want %v", err, os.ErrNotExist)
	}
}

func TestRepairReceiptGroupTransitionRefusesInvalidPredecessorClose(t *testing.T) {
	prepared, r, _, previous := startupPreparedWindow(t, true)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	name, err := ReceiptGroupFileName(previous.GroupID, "close")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.Dir(), name), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	open, _ := prepared.Opening()
	_, err = RepairReceiptGroupTransition(r.Dir(), open.GroupID, prepared.signer, nil, verification.Options{})
	const want = "receipt group predecessor is not complete: invalid receipt group close: receipt group artifact is not canonical published JSON"
	if err == nil || err.Error() != want {
		t.Fatalf("repair error = %v, want %q", err, want)
	}
}
