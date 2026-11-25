// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const defaultIdleFlushDelay = 5 * time.Millisecond

type flushNotification struct {
	callback func(error)
	err      error
}

type actionWriteMode uint8

const (
	writeConfirmed actionWriteMode = iota
	writeBestEffort
	writeObserved
)

// A ticket covers a contiguous range ending at tip. The gate protects its
// disposition and closing done transfers that disposition to its caller.
type writeTicket struct {
	stream      string
	tip         Position
	actions     []Action
	ctx         context.Context
	mode        actionWriteMode
	done        chan struct{}
	observedAt  time.Time
	visible     bool
	withheld    bool
	err         error
	obligations []repairKey
}

func newWriteTicket(ctx context.Context, actions []Action, mode actionWriteMode) *writeTicket {
	return &writeTicket{ctx: ctx, actions: actions, done: make(chan struct{}), mode: mode}
}

func (w *StreamWriter) waitTicket(ticket *writeTicket) error {
	w.release()
	<-ticket.done
	w.gate <- struct{}{}
	return ticket.err
}

// wakeFlush is edge-triggered. The flusher checks the queues again under the
// gate each time it wakes or completes a Sync.
func (w *StreamWriter) wakeFlush() {
	select {
	case w.flushWake <- struct{}{}:
	default:
	}
}

func (w *StreamWriter) notifyChange() {
	close(w.changed)
	w.changed = make(chan struct{})
}

func (w *StreamWriter) waitState(ctx context.Context, waiting func() bool) error {
	for waiting() {
		changed := w.changed
		w.release()
		select {
		case <-changed:
		case <-ctx.Done():
		}
		w.gate <- struct{}{}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (w *StreamWriter) runFlusher() {
	defer close(w.flushDone)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	timer.Stop()
	for {
		w.gate <- struct{}{}
		worked, deadline := w.flushStep()
		notifications := w.notifications
		w.notifications = nil
		w.release()
		for _, notification := range notifications {
			go notification.callback(notification.err)
		}
		if worked {
			continue
		}

		var idle <-chan time.Time
		if !deadline.IsZero() {
			timer.Reset(time.Until(deadline))
			idle = timer.C
		}
		select {
		case <-w.flushStop:
			return
		case <-w.flushWake:
		case <-idle:
		}
		timer.Stop()
	}
}

func (w *StreamWriter) flushStep() (worked bool, deadline time.Time) {
	if w.fatal != nil {
		return false, time.Time{}
	}
	if w.failed() {
		w.recoverRepairs()
		return true, time.Time{}
	}
	if len(w.pending) != 0 {
		if w.waiters == 0 && len(w.repairs) == 0 && !w.draining {
			deadline = w.pending[0].observedAt.Add(w.idleFlushDelay)
			if time.Until(deadline) > 0 {
				return false, deadline
			}
		}
		if w.flushActive() == nil {
			w.releaseReady()
		}
		w.notifyChange()
		return true, time.Time{}
	}
	if len(w.repairs) != 0 {
		w.recoverRepairs()
		return true, time.Time{}
	}
	return false, time.Time{}
}

func (w *StreamWriter) failed() bool {
	return w.previous != nil && w.previous.Ended == endedWriteError
}

// flushActive is called by the flusher with the gate held. Startup repairs
// can also use it before the flusher starts. The in-flight file remains open
// even if an append retires its stream while Sync is running.
func (w *StreamWriter) flushActive() error {
	stream, file, tip := w.active.id, w.active.file, w.active.appended
	w.syncing = true
	w.release()
	err := file.Sync()
	w.gate <- struct{}{}
	w.syncing = false
	if w.active.id != stream || w.active.file == nil {
		_ = file.Close()
		return w.lastWriteErr
	}
	if err != nil {
		err = fmt.Errorf("flush receipt record: %w: %w", errRecordVisible, err)
		w.failGeneration(err, true)
		return err
	}
	w.confirmThrough(tip)
	return nil
}

func (w *StreamWriter) confirmThrough(tip Position) {
	w.active.confirmed = tip
	for len(w.pending) != 0 && w.pending[0].stream == w.active.id && w.pending[0].tip.Seq <= tip.Seq {
		ticket := w.pending[0]
		w.pending[0] = nil
		w.pending = w.pending[1:]
		for _, action := range ticket.actions {
			w.confirmAction(action)
		}
		if ticket.observedAt.IsZero() {
			w.waiters--
			w.markCancelled(ticket)
			w.ready = append(w.ready, ticket)
		}
	}
}

func (w *StreamWriter) markCancelled(ticket *writeTicket) {
	if ticket.err != nil || ticket.mode == writeBestEffort || ticket.ctx.Err() == nil {
		return
	}
	for _, action := range ticket.actions {
		if actionGatesEffect(action) {
			ticket.err = errors.Join(ticket.ctx.Err(), ErrActionPersistStarted)
			w.addTicketRepair(ticket, action, true)
		}
	}
}

func (w *StreamWriter) releaseReady() {
	for len(w.ready) != 0 {
		ticket := w.ready[0]
		w.markCancelled(ticket)
		settled := len(ticket.obligations) != 0
		for _, key := range ticket.obligations {
			if _, pending := w.repairKeys[key]; pending {
				settled = false
				break
			}
		}
		if !settled && len(ticket.obligations) != 0 && w.fatal == nil {
			return
		}
		if settled && ticket.withheld {
			ticket.err = withheldEffect(ticket.err, true)
			if ticket.actions[0].Phase == phaseResolution {
				ticket.err = errors.Join(ticket.err, ErrHoldBlockRecorded)
			}
		}
		if ticket.err != nil && w.fatal != nil {
			ticket.err = errors.Join(ticket.err, w.fatal)
		}
		w.ready[0] = nil
		w.ready = w.ready[1:]
		close(ticket.done)
	}
}

func (w *StreamWriter) failGeneration(err error, syncError bool) {
	w.lastWriteErr = err
	w.durability.FsyncErrorsGated++
	w.retire(endedWriteError)
	delayed := false
	for _, ticket := range w.pending {
		if ticket.mode != writeBestEffort {
			for _, action := range ticket.actions {
				w.addTicketRepair(ticket, action, false)
			}
		}
		if !ticket.observedAt.IsZero() {
			delayed = true
			continue
		}
		ticket.err = err
		if len(ticket.actions) != 0 && ticket.mode != writeBestEffort {
			ticket.err = errors.Join(ErrActionPersistStarted, err)
			if ticket.visible {
				ticket.err = errors.Join(ErrActionVisible, ticket.err)
			}
		}
		w.ready = append(w.ready, ticket)
	}
	w.pending = nil
	w.waiters = 0
	if delayed && syncError && w.onDelayedSyncError != nil {
		w.notifications = append(w.notifications, flushNotification{w.onDelayedSyncError, err})
	}
	w.wakeFlush()
}

func (w *StreamWriter) recoverRepairs() {
	ctx, cancel := context.WithTimeout(context.Background(), writerRepairTimeout)
	defer cancel()
	if err := w.replayActionRepairs(ctx, true); err != nil {
		w.reportFatal(err)
	}
	w.releaseReady()
	w.notifyChange()
}

func (w *StreamWriter) reportFatal(err error) {
	w.fatal = err
	if w.onFatalError != nil {
		w.notifications = append(w.notifications, flushNotification{w.onFatalError, err})
		w.wakeFlush()
	}
}

func (w *StreamWriter) registerTicket(ticket *writeTicket, tip Position) {
	ticket.stream = w.active.id
	ticket.tip = tip
	if ticket.mode == writeObserved {
		ticket.observedAt = time.Now()
	} else {
		w.waiters++
	}
	w.pending = append(w.pending, ticket)
	w.wakeFlush()
}

func (w *StreamWriter) drainSegment(ctx context.Context) error {
	transition := w.transition
	w.transition = true
	defer func() {
		w.transition = transition
		w.notifyChange()
	}()
	return w.drainForEnd(ctx, true)
}

func (w *StreamWriter) busy(includeOutcomes bool) bool {
	return w.waiters != 0 || len(w.ready) != 0 || len(w.repairs) != 0 || w.failed() ||
		includeOutcomes && len(w.pending) != 0
}

func (w *StreamWriter) hasPendingAction(actionID string) bool {
	for _, queue := range [][]*writeTicket{w.pending, w.ready} {
		for _, ticket := range queue {
			for _, action := range ticket.actions {
				if action.ActionID == actionID {
					return true
				}
			}
		}
	}
	return false
}
