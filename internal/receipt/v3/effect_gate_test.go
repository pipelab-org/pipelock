// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestEffectGateAdmission(t *testing.T) {
	writeErr := errors.New("write failed")
	for _, tc := range []struct {
		name     string
		required bool
		writeErr error
		withhold bool
	}{
		{name: "required success", required: true},
		{name: "optional success"},
		{name: "required write failure", required: true, writeErr: writeErr, withhold: true},
		{name: "optional write failure", writeErr: writeErr},
		{name: "optional recorded refusal", writeErr: errors.Join(writeErr, ErrEffectNotReleased), withhold: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes := 0
			gate := EffectGate{required: tc.required, write: func(_ context.Context, action Action, _ PolicySnapshot) error {
				writes++
				if action.Phase != phaseIntent || action.EffectRelation != relationBefore || action.Attempt == nil {
					t.Fatalf("invalid intent: %+v", action)
				}
				return tc.writeErr
			}}
			token, err := gate.Admit(t.Context(), Action{Verdict: verdictAllow}, PolicySnapshot{})
			if writes != 1 || (err != nil) != tc.withhold || (token != nil) != (tc.writeErr == nil) {
				t.Fatalf("admit: writes=%d token=%v error=%v", writes, token != nil, err)
			}
		})
	}
}

func TestEffectGateDelivery(t *testing.T) {
	flushErr := errors.New("flush failed")
	for _, tc := range []struct {
		name     string
		complete bool
		err      error
		want     string
	}{
		{name: "confirmed", complete: true, want: "completed"},
		{name: "incomplete framing", want: "attempt_unknown"},
		{name: "flush failure", complete: true, err: flushErr, want: "attempt_unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			confirmationRan := false
			var writes []Action
			gate := EffectGate{write: func(_ context.Context, action Action, _ PolicySnapshot) error {
				if action.Phase == phaseOutcome && !confirmationRan {
					t.Fatal("outcome preceded confirmation")
				}
				writes = append(writes, action)
				return nil
			}}
			token, err := gate.Admit(t.Context(), Action{Verdict: verdictAllow}, PolicySnapshot{})
			if err != nil {
				t.Fatal(err)
			}
			err = token.ConfirmDelivery(t.Context(), func() (bool, error) {
				if len(writes) != 1 || writes[0].Phase != phaseIntent {
					t.Fatalf("confirmation must follow intent, got %v", writes)
				}
				confirmationRan = true
				return tc.complete, tc.err
			})
			if !errors.Is(err, tc.err) {
				t.Fatalf("confirmation error = %v, want %v", err, tc.err)
			}
			if err := token.SettleOnExit(t.Context()); err != nil {
				t.Fatal(err)
			}
			if len(writes) != 2 || writes[1].OutcomeClass != tc.want {
				t.Fatalf("writes = %+v, want one outcome %q", writes, tc.want)
			}
		})
	}
}

func TestEffectGateCancellationAfterIntent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var writes []Action
	gate := EffectGate{write: func(writeCtx context.Context, action Action, _ PolicySnapshot) error {
		if err := writeCtx.Err(); err != nil {
			t.Fatalf("write used cancelled context: %v", err)
		}
		writes = append(writes, action)
		cancel()
		return nil
	}}
	token, err := gate.Admit(ctx, Action{Verdict: verdictAllow}, PolicySnapshot{})
	if token != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("admit returned token=%v error=%v", token != nil, err)
	}
	if len(writes) != 2 || writes[1].OutcomeClass != outcomeNotReleased {
		t.Fatalf("writes = %+v, want one not_released outcome", writes)
	}
}

func TestEffectGateCancellationBeforeIntent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	gate := EffectGate{write: func(context.Context, Action, PolicySnapshot) error {
		t.Fatal("cancelled request wrote an intent")
		return nil
	}}
	token, err := gate.Admit(ctx, Action{Verdict: verdictAllow}, PolicySnapshot{})
	if token != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("admit returned token=%v error=%v", token != nil, err)
	}
}

func TestEffectGateWriterBatchAndRefusal(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	primary := writerTestIntent("primary")
	support := writerTestIntent("support")
	support.ParentActionID = primary.ActionID
	actions := []Action{primary, support}
	policy := PolicySnapshot{}
	disabled := NewEffectGate(nil)
	if token, err := disabled.AdmitBatch(t.Context(), actions, policy); token != nil || err != nil {
		t.Fatalf("disabled admission: token=%v error=%v", token, err)
	}
	if err := disabled.Refuse(ctx, primary, policy); err != nil {
		t.Fatal(err)
	}

	opts := writerTestOptions(t.TempDir())
	writer := requireWriter(t, opts, localWriterStorage())
	gate := NewEffectGate(writer)
	if token, err := gate.AdmitBatch(t.Context(), nil, policy); token != nil || err != nil {
		t.Fatalf("empty batch: token=%v error=%v", token, err)
	}
	if err := gate.Refuse(ctx, writerTestIntent("refused"), policy); err != nil {
		t.Fatal(err)
	}
	token, err := gate.AdmitBatch(t.Context(), actions, policy)
	if err != nil || token == nil {
		t.Fatalf("batch admission: token=%v error=%v", token, err)
	}
	if err := token.ConfirmDelivery(t.Context(), func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil || *result.Counts.EffectsCompleted != 2 {
		t.Fatalf("expected two completed actions in valid history: %+v", result)
	}
	if count := writerTestCount(t, result, "blocked"); count != 1 {
		t.Fatalf("blocked decisions = %d, want 1", count)
	}
}

func TestEffectGateContinuesAfterOutcomeWriteFailure(t *testing.T) {
	writeErr := errors.New("outcome write failed")
	var outcomes []string
	gate := EffectGate{writeBatch: func(context.Context, []Action, PolicySnapshot) error { return nil }, write: func(_ context.Context, action Action, _ PolicySnapshot) error {
		if action.Phase == phaseOutcome {
			outcomes = append(outcomes, action.ActionID)
			if action.ActionID == "effect" {
				return writeErr
			}
		}
		return nil
	}}
	token, err := gate.AdmitBatch(t.Context(), []Action{
		{ActionID: "effect", Verdict: verdictAllow},
		{ActionID: "support", Verdict: verdictAllow},
	}, PolicySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if err := token.Refuse(t.Context()); !errors.Is(err, writeErr) {
		t.Fatalf("outcome error = %v, want %v", err, writeErr)
	}
	if err := token.SettleOnExit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 2 || outcomes[0] != "effect" || outcomes[1] != "support" {
		t.Fatalf("outcome submissions = %v", outcomes)
	}
}

func TestEffectGateRecordApproval(t *testing.T) {
	ctx := t.Context()
	writerErr := errors.Join(ErrEffectNotReleased, ErrHoldBlockRecorded)
	var phases []string
	gate := EffectGate{write: func(_ context.Context, action Action, _ PolicySnapshot) error {
		phases = append(phases, action.Phase)
		return writerErr
	}}
	for _, phase := range []string{phaseHold, phaseResolution} {
		err := gate.RecordApproval(ctx, Action{Phase: phase}, PolicySnapshot{})
		if !errors.Is(err, ErrEffectNotReleased) || !errors.Is(err, ErrHoldBlockRecorded) {
			t.Fatalf("%s returned %v, want %v", phase, err, writerErr)
		}
	}
	if err := gate.RecordApproval(ctx, Action{Phase: phaseIntent}, PolicySnapshot{}); err == nil {
		t.Fatal("approval accepted an intent")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := gate.RecordApproval(cancelled, Action{Phase: phaseResolution}, PolicySnapshot{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled approval returned %v", err)
	}
	if len(phases) != 2 || phases[0] != phaseHold || phases[1] != phaseResolution {
		t.Fatalf("unexpected phases written: %v", phases)
	}
	if err := (EffectGate{}).RecordApproval(ctx, Action{Phase: phaseHold}, PolicySnapshot{}); err != nil {
		t.Fatalf("disabled gate returned %v", err)
	}
}
