// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
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
