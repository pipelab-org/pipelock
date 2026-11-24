// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const stateAdmitting = "admitting"

// ReceiptHold confirms hold lifecycle records independently of the legacy
// journal. ConfirmResolution returns the confirmed decision, including a block
// produced by repair. An error means the evidence remains unsettled.
type ReceiptHold struct {
	ConfirmHold       func(context.Context, HeldAction) error
	ConfirmResolution func(context.Context, Resolution) (string, error)
	ConfirmCorrection func(context.Context, Resolution) error
}

// Release is valid only during ResolveReceipt. Commit is the last operation
// before attempting the send. Refuse supplies a settlement only when intent
// admission has started, otherwise the manager confirms a correction.
type Release struct {
	ApprovalContext context.Context
	Commit          func()
	Refuse          func(reason string, settleIntent func() error) Resolution
}

// holdLineage retains only ancestry metadata after a callback settles. All
// fields are protected by Manager.mu.
type holdLineage struct {
	id        string
	depth     int
	parent    *holdLineage
	children  int
	committed bool
	blocked   bool
	settled   bool
	closed    bool
}

func (m *Manager) validateHoldCallbacks(action HeldAction) error {
	if action.Receipt == nil {
		if action.Resolve == nil && action.ResolveWithReleaseRefusal == nil {
			return errors.New("resolve callback is required")
		}
		return nil
	}
	if m.cfg.JournalPath != "" {
		return errors.New("hold confirmation requires journal-free operation")
	}
	receipt := action.Receipt
	if receipt.ConfirmHold == nil || receipt.ConfirmResolution == nil ||
		receipt.ConfirmCorrection == nil || action.ResolveReceipt == nil {
		return errors.New("all receipt hold callbacks are required")
	}
	return nil
}

// admitReceiptHoldLocked reserves even waiting admissions. A named session
// confirms at most one hold at a time so no record can name a parent whose
// hold record failed to persist. A resolving parent remains linkable.
func (m *Manager) admitReceiptHoldLocked(ctx context.Context, action *HeldAction) error {
	ctx, cancel := context.WithDeadline(ctx, action.Deadline)
	defer cancel()
	action.state = stateAdmitting
	m.reserveHoldLocked(action)
	sessionID := action.Authority.SessionID
	for {
		done := m.confirmingSessions[sessionID]
		if done == nil || ctx.Err() != nil {
			break
		}
		m.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
		}
		m.mu.Lock()
	}
	if err := ctx.Err(); err != nil {
		m.dropReceiptAdmissionLocked(action)
		m.mu.Unlock()
		return err
	}
	if err := m.linkHoldLocked(action); err != nil {
		m.dropReceiptAdmissionLocked(action)
		m.mu.Unlock()
		return err
	}
	parent := m.lineage[action.ParentDeferID]
	node := &holdLineage{
		id:      action.DeferID,
		depth:   action.CascadeDepth,
		parent:  parent,
		blocked: action.cascadeBlocked || action.admissionBlock != "",
	}
	if parent != nil {
		parent.children++
	}
	m.lineage[node.id] = node
	action.lineage = node
	done := make(chan struct{})
	if sessionID != "" {
		m.confirmingSessions[sessionID] = done
	}
	// Pass an immutable copy. A concurrent ancestor block can mark node
	// while the writer confirms the hold; it cannot change the parent ID.
	evidence := heldSnapshot(action)
	m.mu.Unlock()
	err := action.Receipt.ConfirmHold(ctx, evidence)
	m.mu.Lock()
	delete(m.confirmingSessions, sessionID)
	close(done)
	if err != nil {
		m.dropReceiptAdmissionLocked(action)
		m.mu.Unlock()
		return fmt.Errorf("confirm defer hold: %w", err)
	}
	m.publishHoldLocked(action)
	m.mu.Unlock()
	return nil
}

func (m *Manager) dropReceiptAdmissionLocked(held *HeldAction) {
	delete(m.holds, held.DeferID)
	m.freeReservationLocked(held)
	if held.lineage != nil {
		held.lineage.settled = true
		m.pruneLineageLocked(held.lineage)
	}
}

func (m *Manager) pruneLineageLocked(node *holdLineage) {
	for node != nil && node.settled && node.children == 0 {
		delete(m.lineage, node.id)
		node = node.parent
		if node != nil {
			node.children--
		}
	}
}

func (m *Manager) notifyHoldChangeLocked() {
	close(m.changed)
	m.changed = make(chan struct{})
}

func (m *Manager) takeHold(ctx context.Context, id, decision, source string, expected *HeldAction, wait bool) (*HeldAction, string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Bind the wait to this admission even if an ID is later reused.
	held := m.holds[id]
	if expected != nil && held != expected {
		return nil, "", "", ErrNotFound
	}
	for {
		if held == nil || m.holds[id] != held || held.state != StateHeld {
			return nil, "", "", ErrNotFound
		}
		if held.Receipt == nil {
			if held.cascadeBlocked {
				decision, source = config.ActionBlock, SourceCascade
			}
			break
		}
		if decision == config.ActionBlock {
			break
		}
		if decision == config.ActionAllow {
			if err := ctx.Err(); err != nil {
				if held.parkedApprovals == 0 {
					m.scheduleBlockedResolveLocked(held)
				}
				return nil, "", "", err
			}
		}
		if held.admissionBlock != "" {
			decision, source = config.ActionBlock, held.admissionBlock
			break
		}
		if held.lineage.blocked {
			decision, source = config.ActionBlock, SourceCascade
			break
		}
		if !time.Now().Before(held.Deadline) {
			decision, source = config.ActionBlock, SourceTimeout
			break
		}
		if decision != config.ActionAllow {
			break
		}
		if ancestorsCommitted(held.lineage) {
			break
		}
		if !wait {
			return nil, "", "", nil
		}
		changed := m.changed
		held.parkedApprovals++
		timer := time.NewTimer(time.Until(held.Deadline))
		m.mu.Unlock()
		select {
		case <-changed:
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
		m.mu.Lock()
		held.parkedApprovals--
	}

	held.state = StateResolving
	delete(m.holds, id)
	held.timer.Stop()
	if held.Receipt == nil {
		m.removeSessionHoldLocked(held.Authority.SessionID, id)
		m.freeReservationLocked(held)
	} else if decision != config.ActionAllow {
		m.closeReceiptLineageLocked(held, false)
	} else {
		m.notifyHoldChangeLocked()
	}
	return held, decision, source, nil
}

func ancestorsCommitted(node *holdLineage) bool {
	for parent := node.parent; parent != nil; parent = parent.parent {
		if !parent.committed {
			return false
		}
	}
	return true
}

func (m *Manager) closeReceiptLineageLocked(held *HeldAction, committed bool) {
	node := held.lineage
	if node.closed {
		return
	}
	node.closed = true
	node.committed = committed
	if !committed {
		m.markLineageBlockedLocked(node)
	}
	m.removeSessionHoldLocked(held.Authority.SessionID, held.DeferID)
	m.notifyHoldChangeLocked()
}

func (m *Manager) markLineageBlockedLocked(node *holdLineage) {
	node.blocked = true
	for _, candidate := range m.lineage {
		for parent := candidate.parent; parent != nil; parent = parent.parent {
			if parent == node {
				candidate.blocked = true
				break
			}
		}
	}
}

func (m *Manager) scheduleBlockedResolveLocked(held *HeldAction) {
	var source string
	switch {
	case held.admissionBlock != "":
		source = held.admissionBlock
	case held.lineage != nil && held.lineage.blocked:
		source = SourceCascade
	default:
		return
	}
	if held.timer != nil {
		held.timer.Stop()
	}
	m.scheduleResolveLocked(held, 0, source)
}

func (m *Manager) closeReceiptLineage(held *HeldAction, committed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeReceiptLineageLocked(held, committed)
}

func (m *Manager) finishReceiptHold(held *HeldAction) {
	m.mu.Lock()
	node := held.lineage
	if !node.closed {
		// Keep waiters closed if a callback exits unexpectedly.
		m.closeReceiptLineageLocked(held, false)
	}
	var descendants []*HeldAction
	if node.blocked {
		for _, child := range m.holds {
			if child.state == StateHeld && child.lineage != nil && child.lineage.blocked && child.parkedApprovals == 0 {
				for parent := child.lineage.parent; parent != nil; parent = parent.parent {
					if parent == node {
						descendants = append(descendants, child)
						break
					}
				}
			}
		}
	}
	node.settled = true
	m.pruneLineageLocked(node)
	m.freeReservationLocked(held)
	m.mu.Unlock()
	for _, child := range descendants {
		m.resolveHeld(child, config.ActionBlock, SourceCascade)
	}
}

func (m *Manager) resolveReceiptHold(ctx context.Context, held *HeldAction, res Resolution) (string, error) {
	if res.FinalDecision != config.ActionAllow {
		m.closeReceiptLineage(held, false)
	}
	applied, err := held.Receipt.ConfirmResolution(ctx, res)
	if err != nil || applied != config.ActionAllow {
		m.closeReceiptLineage(held, false)
		if err != nil || res.FinalDecision == config.ActionAllow {
			res = refuseReceiptRelease(res, ReasonReceiptNotWritten)
		}
		held.ResolveReceipt(res, Release{})
		if err != nil {
			return "", fmt.Errorf("confirm deferred resolution: %w", err)
		}
		return res.FinalDecision, nil
	}

	committed := false
	release := Release{
		ApprovalContext: ctx,
		Commit: func() {
			if res.FinalDecision == config.ActionAllow && !committed {
				m.closeReceiptLineage(held, true)
				committed = true
			}
		},
		Refuse: func(reason string, settleIntent func() error) Resolution {
			if committed || res.FinalDecision != config.ActionAllow {
				return res
			}
			m.closeReceiptLineage(held, false)
			res = refuseReceiptRelease(res, reason)
			if settleIntent == nil {
				err = held.Receipt.ConfirmCorrection(ctx, res)
			} else {
				err = settleIntent()
			}
			return res
		},
	}
	held.ResolveReceipt(res, release)
	if res.FinalDecision == config.ActionAllow && !committed {
		release.Refuse(ReasonReceiptNotWritten, nil)
	}
	if err != nil {
		return "", fmt.Errorf("settle deferred release refusal: %w", err)
	}
	return res.FinalDecision, nil
}

func refuseReceiptRelease(res Resolution, reason string) Resolution {
	res.FinalDecision = config.ActionBlock
	res.ResolutionSource = SourceCancel
	res.Reason = reason
	return res
}
