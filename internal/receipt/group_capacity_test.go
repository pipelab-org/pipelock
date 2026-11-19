// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestReceiptGroupCapacityClosesAfterAdmittedOutcomes(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })

	const ceiling = 3000
	capacity := ael.NewCapacity(ceiling)
	set, err := OpenInitialReceiptShardSet(EmitterConfig{
		NativeCapacity: capacity, Recorder: rec, PrivKey: key, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	}, recorder.DefaultSessionBase, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	opts := set.Admit(EmitOpts{
		ActionID: NewActionID(), Verdict: config.ActionAllow, Method: "GET",
		Transport: "fetch", Target: "https://api.vendor.example/data", DecisionPhase: DecisionPhaseIntent,
	})
	writer, err := set.SelectedEmitter(opts)
	if err != nil {
		t.Fatal(err)
	}
	if writer.NativeCapacity() != capacity {
		t.Fatal("shard did not use the common capacity coordinator")
	}
	opts.NativeLease, err = writer.ReserveNativeRecords(2)
	if err != nil {
		t.Fatal(err)
	}
	defer opts.NativeLease.Release()
	if err := set.EmitDurable(opts); err != nil {
		t.Fatal(err)
	}
	if lease, err := writer.ReserveNativeRecords(2); !errors.Is(err, ael.ErrCapacity) {
		lease.Release()
		t.Fatalf("additional admission = %v", err)
	}
	peer, err := set.SelectedEmitter(set.Admit(EmitOpts{}))
	if err != nil {
		t.Fatal(err)
	}
	if lease, err := peer.ReserveNativeRecords(1); !errors.Is(err, ael.ErrCapacity) {
		lease.Release()
		t.Fatalf("other shard still accepts admissions: %v", err)
	}

	// An unreserved write on the stopped shard fails before either chain
	// advances. The reserved outcome can still settle its original intent.
	if err := writer.EmitHeartbeat(); !errors.Is(err, ael.ErrCapacity) || writer.HealthError() != nil {
		t.Fatalf("unreserved write = %v, health = %v", err, writer.HealthError())
	}
	opts.DecisionPhase = DecisionPhaseOutcome
	if err := set.EmitDurable(opts); err != nil {
		t.Fatal(err)
	}
	opts.NativeLease.Release()
	select {
	case <-capacity.Drained():
	default:
		t.Fatal("completed outcome did not release the capacity drain")
	}
	for _, shard := range set.Emitters() {
		if err := shard.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := shard.EmitTranscriptRoot(shard.Session()); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(shard.nativeAEL.Dir(), "recorders", "pipelock.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > ceiling {
			t.Fatalf("shard overflowed: %d > %d", info.Size(), ceiling)
		}
	}
	if _, err := set.PublishClose(); err != nil {
		t.Fatal(err)
	}
	open, _ := set.Opening()
	result := VerifyReceiptGroup(dir, open.GroupID, []string{open.SignerKey})
	if result.Verdict != GroupValid {
		t.Fatalf("group verdict = %+v", result)
	}
	t.Logf("other shard refused, reserved outcome persisted, group verdict = %s", result.Verdict)

	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPredecessorAEL(dir, recorder.DefaultSessionBase, verification.Options{}); err != nil {
		t.Fatalf("standalone check of grouped sessions: %v", err)
	}
	second, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	next, err := OpenSuccessorReceiptShardSet(EmitterConfig{
		NativeCapacity: ael.NewCapacity(ceiling), Recorder: second, PrivKey: key, ConfigHash: testConfigHash,
		Principal: testPrincipal, Actor: testActor,
	}, recorder.DefaultSessionBase, 2, 0, open.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	nextOpening, _ := next.Opening()
	if nextOpening.PreviousGroupID != open.GroupID || nextOpening.GroupID == open.GroupID {
		t.Fatalf("successor opening = %+v", nextOpening)
	}
	lease, err := next.ProcessEmitter().ReserveNativeRecords(2)
	if err != nil {
		t.Fatalf("successor admission: %v", err)
	}
	lease.Release()
	for _, shard := range next.Emitters() {
		if err := shard.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := shard.EmitTranscriptRoot(shard.Session()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := next.PublishClose(); err != nil {
		t.Fatal(err)
	}
	if result := VerifyReceiptGroup(dir, nextOpening.GroupID, []string{nextOpening.SignerKey}); result.Verdict != GroupValid {
		t.Fatalf("successor group verdict = %+v", result)
	}
	t.Log("verified successor with fresh capacity")
}

func TestNativeTerminalSlotsSurviveExhaustedSupportingSlots(t *testing.T) {
	_, key := generateTestKey(t)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir()}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, Session: session})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	decision := func() EmitOpts {
		return EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Target: "https://api.vendor.example/"}
	}
	tooSmall, err := e.AdmitNative(decision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tooSmall.ReserveNativeTerminal(); !errors.Is(err, ael.ErrInvalidLease) {
		t.Fatalf("wrong terminal admission error: %v", err)
	}
	admission, err := e.AdmitNative(EmitOpts{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	admission, err = admission.ReserveNativeTerminal()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Emit(decision().InheritAdmission(admission)); err != nil {
		t.Fatal(err)
	}
	if err := e.Emit(decision().InheritAdmission(admission)); !errors.Is(err, ael.ErrInvalidLease) {
		t.Fatalf("supporting decision consumed terminal slots: %v", err)
	}
	terminal := decision().InheritAdmission(admission).NativeTerminal()
	if err := e.Emit(terminal); err != nil {
		t.Fatalf("terminal receipt: %v", err)
	}
	admission.ReleaseNativeAdmission()
	if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
		t.Fatal(err)
	}
}
