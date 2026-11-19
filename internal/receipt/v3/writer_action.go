// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
)

const (
	phaseDecision   = "decision"
	phaseHold       = "hold"
	phaseIntent     = "intent"
	phaseOutcome    = "outcome"
	phaseResolution = "resolution"

	verdictAllow         = "allow"
	verdictBlock         = "block"
	approvalBoundary     = "approval_prompt"
	relationAfter        = "after"
	relationNotAttempted = "not_attempted"
	outcomeNotReleased   = "not_released"
)

// WriteAction appends one phase under its decision-time policy. A successful
// return is the receipt barrier for an intent or a hold. Callers still own
// the effect and report its observation as a separate phase.
func (w *StreamWriter) WriteAction(ctx context.Context, action Action, policy PolicySnapshot) error {
	if w == nil {
		return errors.New("receipt writer is unavailable")
	}
	action.Policy = policy.ActionPolicy()
	if err := w.acquire(ctx); err != nil {
		return err
	}
	defer w.release()

	if !actionShape(action, w.open.Coverage.ReceiptsRequired) {
		return errors.New("receipt action does not match its effect phase")
	}
	if err := w.prepareAppend(ctx); err != nil {
		return err
	}
	if err := w.commit(ctx, kindAction, action); err != nil {
		if w.previous != nil && w.previous.Ended == endedWriteError {
			w.queueActionRepair(action, false)
			return w.tryContinueAfterWriteError(ctx, err)
		}
		return err
	}
	if err := ctx.Err(); err != nil && actionGatesEffect(action) {
		w.queueActionRepair(action, true)
		// The request context may no longer wait. Retain the repair if a
		// second I/O error prevents this append from being confirmed.
		return errors.Join(err, w.replayActionRepairs(context.WithoutCancel(ctx), false))
	}
	return nil
}

func actionGatesEffect(action Action) bool {
	return action.Phase == phaseHold || action.Phase == phaseIntent ||
		action.Phase == phaseResolution && action.Verdict == verdictAllow
}

func (w *StreamWriter) queueActionRepair(action Action, confirmed bool) {
	if !confirmed && actionGatesEffect(action) && w.open.Coverage.ReceiptsRequired {
		w.durability.DurabilityBlocks++
	}
	switch action.Phase {
	case phaseIntent:
		action.Phase = phaseOutcome
		action.Verdict = verdictBlock
		action.EffectRelation = relationNotAttempted
		action.OutcomeClass = outcomeNotReleased
	case phaseHold:
		if confirmed {
			action = blockingHoldResolution(action, "request_cancelled", relationNotAttempted, false)
		} else {
			action.Phase = phaseDecision
			action.Verdict = verdictBlock
			action.EffectRelation = relationNotAttempted
			action.Hold = nil
			action.Ask = nil
		}
	case phaseResolution:
		if action.Verdict != verdictAllow {
			return
		}
		source := "durability_failure"
		if confirmed {
			source = "request_cancelled"
		}
		action = blockingHoldResolution(action, source, relationAfter, confirmed)
	case phaseOutcome:
		if confirmed {
			return
		}
	default:
		return
	}
	w.repairs = append(w.repairs, action)
}

func blockingHoldResolution(action Action, source, relation string, correction bool) Action {
	policy := action.Hold.Policy
	if policy == "" {
		policy = action.Hold.ResolutionPolicy
	}
	hold := &Hold{
		ID: action.Hold.ID, Parent: action.Hold.Parent,
		CascadeDepth: action.Hold.CascadeDepth, Linkage: action.Hold.Linkage,
		ResolutionPolicy: policy, ResolutionSource: source,
	}
	if correction {
		hold.Correction = &correction
	}
	action.Phase = phaseResolution
	action.Verdict = verdictBlock
	action.EffectBoundary = approvalBoundary
	action.EffectRelation = relation
	action.Ask = nil
	action.Hold = hold
	return action
}

// A repair remains queued until its own confirmation. In particular, a
// second failed successor must carry the original observation forward.
// Startup retries a failed append before admitting traffic.
func (w *StreamWriter) replayActionRepairs(ctx context.Context, retryWriteErrors bool) error {
	for len(w.repairs) != 0 {
		if err := w.ensureAppendSpace(ctx); err != nil {
			return err
		}
		if err := w.commit(ctx, kindAction, w.repairs[0]); err != nil {
			if retryWriteErrors && w.previous != nil && w.previous.Ended == endedWriteError {
				continue
			}
			return fmt.Errorf("replay receipt action after durability interruption: %w", err)
		}
		w.repairs[0] = Action{}
		w.repairs = w.repairs[1:]
	}
	return nil
}

var actionProjection = registerActionProjection()

func registerActionProjection() *receiptcontent.Producer {
	schema := receiptcontent.Schema{
		Kind: "receipt_v3_action", Fields: map[string]receiptcontent.Class{}, Enums: map[string][]string{},
	}
	addActionProjectionFields(&schema, "", "Action")
	for _, path := range []string{
		"actor", "principal", "delegation_chain[]", "caller.client_id", "caller.issuer",
		"caller.resource", "caller.subject", "hold.id", "hold.parent",
		"session.id", "session.original_id", "session.task_id",
	} {
		schema.Fields[path] = receiptcontent.Identity
	}
	schema.Fields["action_id"] = receiptcontent.ProvenID
	schema.Fields["parent_action_id"] = receiptcontent.ProvenID
	schema.Fields["request_id"] = receiptcontent.ProvenRequestID
	schema.Fields["policy.hash"] = receiptcontent.ComputedDigest
	schema.Fields["normalization.digest"] = receiptcontent.ComputedDigest
	schema.Fields["checker.config_hash"] = receiptcontent.ComputedDigest
	return receiptcontent.Register(schema)
}

// Derive fixed member names and enums from the same schema used for
// verification. All other values remain scan input unless classified above.
func addActionProjectionFields(schema *receiptcontent.Schema, path, shape string) {
	for name, field := range wireFields[shape] {
		child := name
		if path != "" {
			child = path + "." + name
		}
		schema.Fields[child] = receiptcontent.Content
		kind := field.kind
		if item, array := strings.CutPrefix(kind, "[]"); array {
			child += "[]"
			kind = item
			schema.Fields[child] = receiptcontent.Content
		}
		if enum, ok := strings.CutPrefix(kind, "@"); ok {
			schema.Fields[child] = receiptcontent.Enum
			schema.Enums[child] = wireEnums[enum]
		}
		addActionProjectionFields(schema, child, kind)
	}
}
