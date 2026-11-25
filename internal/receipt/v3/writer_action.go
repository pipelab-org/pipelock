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
	relationBefore       = "before"
	relationAfter        = "after"
	relationNotAttempted = "not_attempted"
	outcomeNotReleased   = "not_released"
)

// ErrEffectNotReleased means this writer has recorded that the effect was not
// released. The caller must not release it.
var ErrEffectNotReleased = errors.New("receipt recorded that the effect was not released")

// ErrHoldBlockRecorded reports that a failed allow is already closed by a
// durable blocking resolution. The caller must still withhold the release.
var ErrHoldBlockRecorded = errors.New("receipt recorded the blocking hold resolution")

// ErrActionPersistStarted means the writer started persisting the failed
// action. Any repair of the unconfirmed action belongs to the writer.
var ErrActionPersistStarted = errors.New("receipt action persistence started")

// ErrActionVisible indicates the failed action is visible in the receipt
// stream even though its durability could not be confirmed.
var ErrActionVisible = errors.New("receipt action visible before durability failure")

// WriteAction appends one phase under its decision-time policy. A successful
// return is the receipt barrier for an intent or a hold. Callers still own
// the effect and report its observation as a separate phase.
func (w *StreamWriter) WriteAction(ctx context.Context, action Action, policy PolicySnapshot) error {
	return w.writeAction(ctx, action, policy, false)
}

func (w *StreamWriter) writeAction(ctx context.Context, action Action, policy PolicySnapshot, bestEffort bool) error {
	if w == nil {
		return errors.New("receipt writer is unavailable")
	}
	if err := w.acquire(ctx); err != nil {
		return err
	}
	defer w.release()
	action.Policy = policy.ActionPolicy()
	if !actionShape(action, w.open.Coverage.ReceiptsRequired) {
		return errors.New("receipt action does not match its effect phase")
	}
	if action.Phase == phaseResolution {
		hold, ok := w.holds[action.ActionID]
		if !ok || hold != action.Hold.ID {
			return errors.New("receipt resolution requires a matching active hold")
		}
	}
	if err := w.prepareAppend(ctx); err != nil {
		return err
	}
	if bestEffort {
		// A live optional denial may still be delivered after a failed append.
		// Leave any unconfirmed intent as a gap instead of recording a refusal.
		_, err := w.appendRecord(ctx, kindAction, action)
		if err != nil {
			return w.tryContinueAfterWriteError(ctx, err)
		}
		return nil
	}
	started, err := w.appendAction(ctx, action)
	if started && err != nil {
		err = errors.Join(ErrActionPersistStarted, err)
	}
	return err
}

func (w *StreamWriter) appendAction(ctx context.Context, action Action) (persistStarted bool, err error) {
	persistStarted, err = w.appendRecord(ctx, kindAction, action)
	if err != nil {
		if persistStarted {
			withheld := w.queueActionRepair(action, false)
			visible := errors.Is(err, errRecordVisible)
			err = w.tryContinueAfterWriteError(ctx, err)
			if visible {
				err = errors.Join(ErrActionVisible, err)
			}
			return true, w.withheldAction(err, action, withheld)
		}
		return false, err
	}
	w.confirmAction(action)
	if err := ctx.Err(); err != nil && actionGatesEffect(action) {
		withheld := w.queueActionRepair(action, true)
		return true, w.withheldAction(errors.Join(err, w.settleActionRepairs(ctx)), action, withheld)
	}
	return true, nil
}

func (w *StreamWriter) withheldAction(err error, action Action, withheld bool) error {
	withheld = withheld && len(w.repairs) == 0
	if withheld && action.Phase == phaseResolution {
		err = errors.Join(ErrHoldBlockRecorded, err)
	}
	return withheldEffect(err, withheld)
}

// WriteAdmissionBatch reserves consecutive positions for the intents and
// confirms all of them together before the caller can attempt the effect.
func (w *StreamWriter) WriteAdmissionBatch(ctx context.Context, actions []Action, policy PolicySnapshot) error {
	if len(actions) == 0 {
		return nil
	}
	if w == nil {
		return errors.New("receipt writer is unavailable")
	}
	if err := w.acquire(ctx); err != nil {
		return err
	}
	defer w.release()

	seen := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		if action.Phase != phaseIntent || !actionShape(action, w.open.Coverage.ReceiptsRequired) {
			return errors.New("receipt batch requires admission actions")
		}
		if _, duplicate := seen[action.ActionID]; duplicate {
			return errors.New("receipt batch repeats an action ID")
		}
		seen[action.ActionID] = struct{}{}
	}
	if err := w.prepareAppend(ctx); err != nil {
		return err
	}
	if int64(len(actions)) > maxInteger-2-w.active.confirmed.Seq {
		if err := w.rollover(ctx); err != nil {
			return err
		}
	}
	first := w.active.confirmed.Seq + 1
	tip := w.active.confirmed
	var batch []byte
	for _, action := range actions {
		action.Policy = policy.ActionPolicy()
		tip.Seq++
		line, pos, err := w.encode(ctx, w.common(kindAction, w.active.id, tip.Record, tip.Seq), action)
		if err != nil {
			return err
		}
		if len(line) > w.fileBytes-maxLineBytes-len(batch) {
			return errors.New("receipt admission batch exceeds the segment limit")
		}
		batch = append(batch, line...)
		tip.Record = pos
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := w.persist(kindAction, batch, first); err != nil {
		w.durability.FsyncErrorsGated++
		w.retire(endedWriteError)
		for _, action := range actions {
			action.Policy = policy.ActionPolicy()
			w.queueActionRepair(action, false)
		}
		err = w.tryContinueAfterWriteError(ctx, err)
		return withheldEffect(err, len(w.repairs) == 0)
	}
	w.active.confirmed = tip
	for _, action := range actions {
		w.confirmAction(action)
	}
	if err := ctx.Err(); err != nil {
		for _, action := range actions {
			action.Policy = policy.ActionPolicy()
			w.queueActionRepair(action, true)
		}
		repairErr := w.settleActionRepairs(ctx)
		return withheldEffect(errors.Join(err, repairErr), repairErr == nil)
	}
	return nil
}

func (w *StreamWriter) confirmAction(action Action) {
	switch action.Phase {
	case phaseHold:
		w.holds[action.ActionID] = action.Hold.ID
	case phaseResolution:
		if action.Verdict != verdictAllow {
			delete(w.holds, action.ActionID)
		}
	case phaseIntent, phaseOutcome:
		delete(w.holds, action.ActionID)
	}
}

func withheldEffect(err error, withheld bool) error {
	if withheld {
		err = errors.Join(ErrEffectNotReleased, err)
	}
	return err
}

func actionGatesEffect(action Action) bool {
	return action.Phase == phaseHold || action.Phase == phaseIntent ||
		action.Phase == phaseResolution && action.Verdict == verdictAllow
}

// queueActionRepair reports whether the repair says the effect was not released.
func (w *StreamWriter) queueActionRepair(action Action, confirmed bool) bool {
	if !confirmed && actionGatesEffect(action) && w.open.Coverage.ReceiptsRequired {
		w.durability.DurabilityBlocks++
	}
	switch action.Phase {
	case phaseIntent:
		action = minimalRepairAction(action)
		action.Phase = phaseOutcome
		action.Verdict = verdictBlock
		action.EffectRelation = relationNotAttempted
		action.OutcomeClass = outcomeNotReleased
	case phaseHold:
		if confirmed {
			action = blockingHoldResolution(action, "request_cancelled", relationNotAttempted, false)
		} else {
			action = minimalRepairAction(action)
			action.Phase = phaseDecision
			action.Verdict = verdictBlock
			action.EffectRelation = relationNotAttempted
		}
	case phaseResolution:
		if action.Verdict != verdictAllow {
			// A correcting block supersedes an already confirmed allow.
			// Preserve it across successor streams even though it cannot
			// grant authority for an effect.
			if action.Hold.Correction != nil && *action.Hold.Correction {
				w.repairs = append(w.repairs, action)
				return true
			}
			return false
		}
		source := "durability_failure"
		if confirmed {
			source = "request_cancelled"
		}
		action = blockingHoldResolution(action, source, relationAfter, confirmed)
	case phaseOutcome:
		if confirmed {
			return false
		}
		w.repairs = append(w.repairs, minimalRepairAction(action))
		return action.OutcomeClass == outcomeNotReleased
	default:
		return false
	}
	w.repairs = append(w.repairs, action)
	return true
}

// Keep required wire members and identities used by lifecycle appraisal.
func minimalRepairAction(action Action) Action {
	repair := Action{
		ActionID: action.ActionID, ActionType: action.ActionType,
		Actor: action.Actor, Principal: action.Principal,
		Caller:         Caller{Authn: "none"},
		Data:           Data{Reversibility: action.Data.Reversibility, SideEffectClass: action.Data.SideEffectClass},
		EffectBoundary: action.EffectBoundary, EffectRelation: action.EffectRelation,
		Target: action.Target, Transport: action.Transport,
		Attempt: action.Attempt, OutcomeClass: action.OutcomeClass,
		Phase: action.Phase, Verdict: action.Verdict, Policy: action.Policy,
		RequestID: action.RequestID,
	}
	if action.Attempt != nil {
		repair.Method = action.Method
	}
	return repair
}

func blockingHoldResolution(action Action, source, relation string, correction bool) Action {
	policy := action.Hold.Policy
	if policy == "" {
		policy = action.Hold.ResolutionPolicy
	}
	hold := &Hold{
		ID:               action.Hold.ID,
		ResolutionPolicy: policy, ResolutionSource: source,
	}
	if correction {
		hold.Correction = &correction
	}
	action = minimalRepairAction(action)
	action.Phase = phaseResolution
	action.Verdict = verdictBlock
	action.EffectBoundary = approvalBoundary
	action.EffectRelation = relation
	action.Hold = hold
	return action
}

// A repair remains queued until its own confirmation. In particular, a
// second failed successor must carry the original observation forward.
// Give each repair one retry on a new successor before requiring recovery.
func (w *StreamWriter) replayActionRepairs(ctx context.Context, retryWriteErrors bool) error {
	retried := false
	for len(w.repairs) != 0 {
		if err := w.ensureAppendSpace(ctx); err != nil {
			return err
		}
		action := w.repairs[0]
		err := w.commit(ctx, kindAction, action)
		if err != nil {
			if retryWriteErrors && !retried && w.previous != nil && w.previous.Ended == endedWriteError {
				retried = true
				continue
			}
			return fmt.Errorf("replay receipt action after durability interruption: %w", err)
		}
		w.confirmAction(action)
		w.repairs[0] = Action{}
		w.repairs = w.repairs[1:]
		retried = false
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
	schema.Fields["session.task_id"] = receiptcontent.ProvenTaskID
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
