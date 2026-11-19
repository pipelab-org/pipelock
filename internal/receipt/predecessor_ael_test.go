// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestVerifyPredecessorAELAllowsVerifiedOpenPrefix(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	rec := newTestRecorder(t, dir, key)
	t.Cleanup(func() { _ = rec.Close() })
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	emitter := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, Session: session})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if err := emitter.EmitDurable(EmitOpts{ActionID: NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Target: "https://api.vendor.example/data"}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPredecessorAEL(dir, recorder.DefaultSessionBase, verification.Options{}); err != nil {
		t.Fatalf("live writer blocked startup: %v", err)
	}
	if err := emitter.AbortNativeAEL(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := VerifyPredecessorAEL(dir, recorder.DefaultSessionBase, verification.Options{Context: ctx}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification: %v", err)
	}
	if err := VerifyPredecessorAEL(dir, recorder.DefaultSessionBase, verification.Options{}); err != nil {
		t.Fatalf("valid open prefix: %v", err)
	}
}

func TestVerifyPredecessorAELPreservesLegacyContinuity(t *testing.T) {
	dir := t.TempDir()
	_, key := generateTestKey(t)
	seedTamperedTail(t, dir, key)

	if err := VerifyPredecessorAEL(dir, recorder.DefaultSessionBase, verification.Options{}); err != nil {
		t.Fatalf("a legacy tail previously skipped by the linker blocked startup: %v", err)
	}
	if err := VerifyPredecessorAEL(filepath.Join(dir, "missing"), recorder.DefaultSessionBase, verification.Options{}); err == nil {
		t.Fatal("accepted a missing recorder directory")
	}
}

func TestVerifyPredecessorAELRefusesOversizedSealedRun(t *testing.T) {
	_, key := generateTestKey(t)
	dir := t.TempDir()
	rec := newTestRecorder(t, dir, key)
	t.Cleanup(func() {
		if err := rec.Close(); err != nil {
			t.Error(err)
		}
	})
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	emitter := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, Session: session})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if err := emitter.EmitSessionClose("fixture complete"); err != nil {
		t.Fatal(err)
	}
	if err := emitter.EmitTranscriptRoot(session); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPredecessorAEL(dir, recorder.DefaultSessionBase, verification.Options{}); err != nil {
		t.Fatalf("sealed predecessor = %v", err)
	}
	if err := os.Truncate(filepath.Join(emitter.nativeAEL.Dir(), "recorders", "pipelock.jsonl"), (256<<20)+1); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPredecessorAEL(dir, recorder.DefaultSessionBase, verification.Options{}); !errors.Is(err, ael.ErrStreamTooLarge) {
		t.Fatalf("oversized predecessor = %v, want %v", err, ael.ErrStreamTooLarge)
	}
}
