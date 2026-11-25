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
	return w.writeAction(ctx, action, policy, writeConfirmed)
}

func (w *StreamWriter) writeAction(ctx context.Context, action Action, policy PolicySnapshot, mode actionWriteMode) error {
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
	if err := w.prepareAppend(ctx, 1); err != nil {
		return err
	}
	if action.Phase == phaseResolution {
		for {
			hold, ok := w.holds[action.ActionID]
			if !ok || hold != action.Hold.ID {
				return errors.New("receipt resolution requires a matching active hold")
			}
			if !w.hasPendingAction(action.ActionID) {
				break
			}
			if err := w.waitState(ctx, func() bool {
				return w.fatal == nil && (w.transition || w.failed() || len(w.repairs) != 0 || w.hasPendingAction(action.ActionID))
			}); err != nil {
				return err
			}
			if err := w.prepareAppend(ctx, 1); err != nil {
				return err
			}
		}
	}
	pendingAction := action
	if mode == writeObserved {
		// The caller may reuse its data as soon as the observation is
		// acknowledged. Retain only the fields needed by repair.
		pendingAction = minimalRepairAction(action)
		attempt := *action.Attempt
		pendingAction.Attempt = &attempt
	}
	ticket := newWriteTicket(ctx, []Action{pendingAction}, mode)
	if err := w.appendRecord(ctx, kindAction, action, ticket); err != nil {
		return err
	}
	if mode == writeObserved {
		return nil
	}
	return w.waitTicket(ticket)
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
	batch := make([]Action, 0, len(actions))
	for _, action := range actions {
		if action.Phase != phaseIntent || !actionShape(action, w.open.Coverage.ReceiptsRequired) {
			return errors.New("receipt batch requires admission actions")
		}
		if _, duplicate := seen[action.ActionID]; duplicate {
			return errors.New("receipt batch repeats an action ID")
		}
		seen[action.ActionID] = struct{}{}
		action.Policy = policy.ActionPolicy()
		batch = append(batch, action)
	}
	if err := w.prepareAppend(ctx, int64(len(batch))); err != nil {
		return err
	}
	ticket := newWriteTicket(ctx, batch, writeConfirmed)
	if err := w.appendBatch(ctx, ticket); err != nil {
		return err
	}
	return w.waitTicket(ticket)
}

func (w *StreamWriter) appendBatch(ctx context.Context, ticket *writeTicket) error {
	for {
		before := w.active.appended
		tip := before
		var batch []byte
		for _, action := range ticket.actions {
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
		if w.needsSegment(kindAction, len(batch)) && before != w.active.confirmed {
			if err := w.drainSegment(ctx); err != nil {
				return err
			}
			if before != w.active.appended {
				continue
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return w.appendLines(kindAction, batch, before.Seq+1, tip, ticket)
	}
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

type repairKey struct {
	action, phase, hold, outcome, verdict, relation, boundary string
	attempt                                                   int64
	correction                                                bool
}

func (w *StreamWriter) addTicketRepair(ticket *writeTicket, action Action, confirmed bool) {
	key, queued := w.queueActionRepair(action, confirmed)
	if queued {
		ticket.obligations = append(ticket.obligations, key)
		ticket.withheld = ticket.withheld || actionGatesEffect(action) ||
			action.Phase == phaseResolution && action.Verdict == verdictBlock ||
			action.Phase == phaseOutcome && action.OutcomeClass == outcomeNotReleased
	}
}

func (w *StreamWriter) queueActionRepair(action Action, confirmed bool) (repairKey, bool) {
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
		if action.Verdict == verdictAllow {
			source := "durability_failure"
			if confirmed {
				source = "request_cancelled"
			}
			action = blockingHoldResolution(action, source, relationAfter, confirmed)
		}
	case phaseOutcome:
		action = minimalRepairAction(action)
	default:
		return repairKey{}, false
	}
	return w.enqueueRepair(action), true
}

func actionRepairKey(action Action) repairKey {
	key := repairKey{
		action: action.ActionID, phase: action.Phase, outcome: action.OutcomeClass,
		verdict: action.Verdict, relation: action.EffectRelation, boundary: action.EffectBoundary,
	}
	if action.Hold != nil {
		key.hold = action.Hold.ID
		key.correction = action.Hold.Correction != nil && *action.Hold.Correction
	}
	if action.Attempt != nil {
		key.attempt = *action.Attempt
	}
	return key
}

func (w *StreamWriter) enqueueRepair(action Action) repairKey {
	key := actionRepairKey(action)
	if _, pending := w.repairKeys[key]; !pending {
		w.repairKeys[key] = struct{}{}
		w.repairs = append(w.repairs, action)
	}
	return key
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
	if action.Phase == phaseOutcome {
		repair.ParentActionID = action.ParentActionID
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
	for w.failed() || len(w.repairs) != 0 {
		if err := w.ensureStream(ctx); err != nil {
			return err
		}
		if len(w.repairs) == 0 {
			break
		}
		action := w.repairs[0]
		err := w.appendRecord(ctx, kindAction, action, nil)
		if err == nil && w.active.appended != w.active.confirmed {
			err = w.flushActive()
		}
		if err != nil {
			if retryWriteErrors && !retried && w.failed() {
				retried = true
				continue
			}
			return fmt.Errorf("replay receipt action after durability interruption: %w", err)
		}
		w.confirmAction(action)
		delete(w.repairKeys, actionRepairKey(action))
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
