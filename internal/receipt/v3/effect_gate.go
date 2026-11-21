// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"
)

// EffectGate owns receipt admission and settlement for one stream. A zero gate
// disables receipt recording. Required mode withholds on every admission write
// error. Optional mode withholds when the writer reports ErrEffectNotReleased,
// since the writer then owns the refusal. An error from Admit prohibits release.
// A nil token with no error means release may proceed without a recorded intent.
type EffectGate struct {
	write               func(context.Context, Action, PolicySnapshot) error
	writeBatch          func(context.Context, []Action, PolicySnapshot) error
	required            bool
	finalizationTimeout time.Duration
}

// NewEffectGate uses the required mode pinned in the stream's opening record.
func NewEffectGate(writer *StreamWriter) EffectGate {
	if writer == nil {
		return EffectGate{}
	}
	return EffectGate{
		write: writer.WriteAction, writeBatch: writer.WriteAdmissionBatch,
		required: writer.open.Coverage.ReceiptsRequired,
	}
}

// WithFinalizationTimeout bounds admission of a refusal or terminal outcome
// after transport cancellation. It cannot interrupt a file sync already underway.
func (g EffectGate) WithFinalizationTimeout(timeout time.Duration) EffectGate {
	g.finalizationTimeout = timeout
	return g
}

func (g EffectGate) finalizationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx = context.WithoutCancel(ctx)
	if g.finalizationTimeout > 0 {
		return context.WithTimeout(ctx, g.finalizationTimeout)
	}
	return ctx, func() {}
}

// EffectToken identifies one admitted attempt. Keep it by pointer and defer
// SettleOnExit immediately after Admit. A terminal method submits the outcome
// once, including if the write fails. The stream writer owns durability repair.
type EffectToken struct {
	gate    EffectGate
	actions []Action
	policy  PolicySnapshot
	once    sync.Once
}

// Admit writes the intent before the caller may attempt the effect. The action
// supplies its identity, verdict and boundary. The gate sets its phase and
// attempt fields. Each independently released effect needs its own action ID.
func (g EffectGate) Admit(ctx context.Context, action Action, policy PolicySnapshot) (*EffectToken, error) {
	return g.admit(ctx, []Action{action}, policy)
}

// AdmitBatch admits all actions as one effect. All share one confirmation and
// settle from the same observation. The first action identifies the primary
// decision and supporting actions may reference it by ID.
func (g EffectGate) AdmitBatch(ctx context.Context, actions []Action, policy PolicySnapshot) (*EffectToken, error) {
	return g.admit(ctx, slices.Clone(actions), policy)
}

func (g EffectGate) admit(ctx context.Context, actions []Action, policy PolicySnapshot) (*EffectToken, error) {
	if g.write == nil || len(actions) == 0 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	attempt := int64(1)
	for i := range actions {
		actions[i].Attempt = &attempt
		actions[i].Phase = phaseIntent
		actions[i].EffectRelation = relationBefore
		actions[i].OutcomeClass = ""
	}
	err := g.writeIntents(ctx, actions, policy)
	if err != nil {
		if g.required || errors.Is(err, ErrEffectNotReleased) {
			return nil, err
		}
		return nil, ctx.Err()
	}
	token := &EffectToken{gate: g, actions: actions, policy: policy}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, token.Refuse(ctx))
	}
	return token, nil
}

func (g EffectGate) writeIntents(ctx context.Context, actions []Action, policy PolicySnapshot) error {
	if len(actions) == 1 {
		return g.write(ctx, actions[0], policy)
	}
	return g.writeBatch(ctx, actions, policy)
}

// RecordApproval records a hold or its resolution under the caller's
// deadline. These records change the durable hold lifecycle even in optional
// receipt mode, so every write error is returned, including writer recovery
// results. Releasing an approved effect still requires Admit.
func (g EffectGate) RecordApproval(ctx context.Context, action Action, policy PolicySnapshot) error {
	if g.write == nil {
		return nil
	}
	if action.Phase != phaseHold && action.Phase != phaseResolution {
		return errors.New("receipt approval requires a hold or resolution")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return g.write(ctx, action, policy)
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
	ctx, cancel := g.finalizationContext(ctx)
	defer cancel()
	return g.write(ctx, action, policy)
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
	var err error
	t.once.Do(func() {
		ctx, cancel := t.gate.finalizationContext(ctx)
		defer cancel()
		for _, action := range t.actions {
			action.Phase = phaseOutcome
			action.OutcomeClass = outcome
			action.EffectRelation = relation
			if verdict != "" {
				action.Verdict = verdict
			}
			err = errors.Join(err, t.gate.write(ctx, action, t.policy))
		}
	})
	return err
}
