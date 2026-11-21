// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"errors"
	"sync"
)

// EffectGate owns receipt admission and settlement for one stream. A zero gate
// disables receipt recording. Required mode withholds on every admission write
// error. Optional mode withholds when the writer reports ErrEffectNotReleased,
// since the writer then owns the refusal. An error from Admit prohibits release.
// A nil token with no error means release may proceed without a recorded intent.
type EffectGate struct {
	write    func(context.Context, Action, PolicySnapshot) error
	required bool
}

// NewEffectGate uses the required mode pinned in the stream's opening record.
func NewEffectGate(writer *StreamWriter) EffectGate {
	if writer == nil {
		return EffectGate{}
	}
	return EffectGate{write: writer.WriteAction, required: writer.open.Coverage.ReceiptsRequired}
}

// EffectToken identifies one admitted attempt. Keep it by pointer and defer
// SettleOnExit immediately after Admit. A terminal method submits the outcome
// once, including if the write fails. The stream writer owns durability repair.
type EffectToken struct {
	gate   EffectGate
	action Action
	policy PolicySnapshot
	once   sync.Once
	err    error
}

// Admit writes the intent before the caller may attempt the effect. The action
// supplies its identity, verdict and boundary. The gate sets its phase and
// attempt fields. Each independently released effect needs its own action ID.
func (g EffectGate) Admit(ctx context.Context, action Action, policy PolicySnapshot) (*EffectToken, error) {
	if g.write == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	attempt := int64(1)
	action.Attempt = &attempt
	action.Phase = phaseIntent
	action.EffectRelation = relationBefore
	action.OutcomeClass = ""
	if err := g.write(ctx, action, policy); err != nil {
		if g.required || errors.Is(err, ErrEffectNotReleased) {
			return nil, err
		}
		return nil, ctx.Err()
	}
	token := &EffectToken{gate: g, action: action, policy: policy}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, token.Refuse(ctx))
	}
	return token, nil
}

// Refuse records a blocking decision for an effect that was never admitted.
func (g EffectGate) Refuse(ctx context.Context, action Action, policy PolicySnapshot) error {
	if g.write == nil {
		return nil
	}
	action.Attempt = nil
	action.OutcomeClass = ""
	action.Phase = phaseDecision
	action.Verdict = verdictBlock
	action.EffectRelation = relationNotAttempted
	return g.write(context.WithoutCancel(ctx), action, policy)
}

// Refuse settles an admitted intent whose effect is known never to have started.
func (t *EffectToken) Refuse(ctx context.Context) error {
	return t.settle(ctx, outcomeNotReleased, relationNotAttempted, verdictBlock)
}

// ConfirmDelivery settles after the transport's confirmation runs. Confirmation
// returns true only when the effect was observed, including any needed flush and
// final framing. Handler return, successful writes, and an interim response
// alone do not establish final HTTP framing. A failed or incomplete confirmation
// records attempt_unknown. A nil token still runs confirmation.
func (t *EffectToken) ConfirmDelivery(ctx context.Context, confirm func() (bool, error)) error {
	complete, err := confirm()
	if err != nil || !complete {
		return errors.Join(err, t.SettleOnExit(ctx))
	}
	return t.settle(ctx, "completed", relationAfter, "")
}

// SettleOnExit records attempt_unknown when no stronger observation settled the
// intent. It is safe after any terminal method and on a nil token.
func (t *EffectToken) SettleOnExit(ctx context.Context) error {
	return t.settle(ctx, "attempt_unknown", "unknown", "")
}

func (t *EffectToken) settle(ctx context.Context, outcome, relation, verdict string) error {
	if t == nil {
		return nil
	}
	t.once.Do(func() {
		action := t.action
		action.Phase = phaseOutcome
		action.OutcomeClass = outcome
		action.EffectRelation = relation
		if verdict != "" {
			action.Verdict = verdict
		}
		t.err = t.gate.write(context.WithoutCancel(ctx), action, t.policy)
	})
	return t.err
}
