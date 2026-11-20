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

// WriteAction appends one phase under its decision-time policy. A successful
// return is the receipt barrier for an intent or a hold. Callers still own
// the effect and report its observation as a separate phase.
func (w *StreamWriter) WriteAction(ctx context.Context, action Action, policy PolicySnapshot) error {
	if w == nil {
		return errors.New("receipt writer is unavailable")
	}
	if err := w.acquire(ctx); err != nil {
		return err
	}
	defer w.release()
	action.Policy = policy.ActionPolicy()
	return w.writeAction(ctx, action)
}

// WriteTerminalResolution retains a hold's non-releasing resolution if the
// deadline expires while waiting for the writer. The caller still receives
// the admission error. Only a known pre-append failure enters this queue.
func (w *StreamWriter) WriteTerminalResolution(ctx context.Context, action Action, policy PolicySnapshot, maxPending int) error {
	if w == nil {
		return ErrWriterUnavailable
	}
	action.Policy = policy.ActionPolicy()
	if action.Phase != phaseResolution || releases(action.Verdict) ||
		!actionShape(action, w.open.Coverage.ReceiptsRequired) {
		return errors.New("receipt action is not a terminal hold resolution")
	}
	if err := w.acquire(ctx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(err, w.queueTerminalResolution(action, maxPending))
		}
		return err
	}
	defer w.release()
	return w.writeAction(ctx, action)
}

func (w *StreamWriter) queueTerminalResolution(action Action, maxPending int) error {
	w.terminalMu.Lock()
	defer w.terminalMu.Unlock()
	if w.terminalClosed {
		return ErrWriterUnavailable
	}
	if len(w.terminalPending) >= maxPending {
		return errors.New("terminal receipt resolution queue is full")
	}
	startWorker := len(w.terminalPending) == 0
	w.terminalPending = append(w.terminalPending, action)
	if startWorker {
		go w.flushTerminalResolutions()
	}
	return nil
}

func (w *StreamWriter) flushTerminalResolutions() {
	w.gate <- struct{}{}
	defer w.release()
	if !w.collectTerminalResolutions(false) {
		return
	}
	// Uses the same repair and successor rules as a failed synchronous flush.
	if err := w.settleActionRepairs(context.Background()); err != nil {
		w.collectTerminalResolutions(true)
	}
}

// collectTerminalResolutions runs under the writer gate. Close collects
// accepted work even when it acquires the gate before the worker.
func (w *StreamWriter) collectTerminalResolutions(closing bool) bool {
	w.terminalMu.Lock()
	defer w.terminalMu.Unlock()
	if closing {
		w.terminalClosed = true
	}
	if len(w.terminalPending) == 0 {
		return false
	}
	w.repairs = append(w.repairs, w.terminalPending...)
	w.terminalPending = nil
	return true
}

func (w *StreamWriter) writeAction(ctx context.Context, action Action) error {
	if !actionShape(action, w.open.Coverage.ReceiptsRequired) {
		return errors.New("receipt action does not match its effect phase")
	}
	if err := w.prepareAppend(ctx); err != nil {
		return err
	}
	if err := w.commit(ctx, kindAction, action); err != nil {
		if w.previous != nil && w.previous.Ended == endedWriteError {
			withheld := w.queueActionRepair(action, false)
			err = w.tryContinueAfterWriteError(ctx, err)
			return w.withheldAction(err, action, withheld)
		}
		return err
	}
	if err := ctx.Err(); err != nil && actionGatesEffect(action) {
		withheld := w.queueActionRepair(action, true)
		return w.withheldAction(errors.Join(err, w.settleActionRepairs(ctx)), action, withheld)
	}
	return nil
}

func (w *StreamWriter) withheldAction(err error, action Action, withheld bool) error {
	if withheld && action.Phase == phaseResolution && len(w.repairs) == 0 {
		err = errors.Join(ErrHoldBlockRecorded, err)
	}
	return withheldEffect(err, withheld)
}

// WriteAdmissionBatch reserves consecutive positions for the actions and
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
		if (action.Phase != phaseIntent && action.Phase != phaseDecision) ||
			action.EffectRelation != relationBefore || !releases(action.Verdict) || !actionShape(action, w.open.Coverage.ReceiptsRequired) {
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
		withheld := false
		for _, action := range actions {
			action.Policy = policy.ActionPolicy()
			withheld = w.queueActionRepair(action, false) || withheld
		}
		return withheldEffect(w.tryContinueAfterWriteError(ctx, err), withheld)
	}
	w.active.confirmed = tip
	if err := ctx.Err(); err != nil {
		withheld := false
		for _, action := range actions {
			if action.Phase == phaseIntent {
				action.Policy = policy.ActionPolicy()
				withheld = w.queueActionRepair(action, true) || withheld
			}
		}
		return withheldEffect(errors.Join(err, w.settleActionRepairs(ctx)), withheld)
	}
	return nil
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
			// The manager already applied this terminal decision.
			if !confirmed {
				w.repairs = append(w.repairs, action)
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
		w.repairs = append(w.repairs, action)
		return false
	default:
		return false
	}
	w.repairs = append(w.repairs, action)
	return true
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
// Give each repair one retry on a new successor before requiring recovery.
func (w *StreamWriter) replayActionRepairs(ctx context.Context, retryWriteErrors bool) error {
	retried := false
	for len(w.repairs) != 0 {
		if err := w.ensureAppendSpace(ctx); err != nil {
			return err
		}
		if err := w.commit(ctx, kindAction, w.repairs[0]); err != nil {
			if retryWriteErrors && !retried && w.previous != nil && w.previous.Ended == endedWriteError {
				retried = true
				continue
			}
			return fmt.Errorf("replay receipt action after durability interruption: %w", err)
		}
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
