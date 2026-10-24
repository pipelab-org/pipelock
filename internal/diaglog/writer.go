// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package diaglog serializes operator output and bounds optional diagnostic I/O.
package diaglog

import (
	"io"
	"sync"
	"syscall"
	"time"
)

// Writer shares one lock for ordinary output and optional diagnostics. Ordinary
// writes always wait their turn and return the sink's actual result, including
// errors. Only optional diagnostics are skipped when the sink is busy.
// Diagnostics are best-effort, with one in-flight message and no pending queue.
// A permanently wedged sink retains at most one diagnostic goroutine per Writer.
type Writer struct {
	w       io.Writer
	mu      sync.Mutex
	state   sync.Mutex
	pending chan struct{}
	closed  bool
}

// New returns the existing shared writer when available. Owners must retain and
// reuse it across requests and reloads, rather than wrap a raw sink per message.
func New(w io.Writer) *Writer {
	if w == nil {
		return nil
	}
	if shared, ok := w.(interface{ DiagnosticWriter() *Writer }); ok {
		return shared.DiagnosticWriter()
	}
	return &Writer{w: w}
}

// FlushGrace is the existing bounded operator-log grace period. A healthy sink
// settles within it; an arbitrary blocked io.Writer cannot be cancelled.
const FlushGrace = time.Second

// Scope establishes an owner only when the caller has not supplied one. The
// returned finish function drains the writer, but only closes an owner created
// here. Nested consumers leave a caller-owned writer open for other producers.
func Scope(w io.Writer) (*Writer, func()) {
	if shared, ok := w.(interface{ DiagnosticWriter() *Writer }); ok {
		owner := shared.DiagnosticWriter()
		return owner, owner.Flush
	}
	owner := New(w)
	return owner, owner.Close
}

// Stop prevents further optional admission. Ordinary Write remains synchronous.
func (w *Writer) Stop() {
	if w == nil {
		return
	}
	w.state.Lock()
	w.closed = true
	w.state.Unlock()
}

// Close stops optional admission and waits at most FlushGrace for the already
// admitted write. A timed-out write may start or finish later: io.Writer has no
// cancellation contract. At most one optional goroutine can outlive this owner;
// callers of a wedged sink must not reuse it unsafely until that write settles.
func (w *Writer) Close() {
	if w == nil {
		return
	}
	w.Stop()
	w.Flush()
}

// Flush gives an already-admitted diagnostic a bounded delivery attempt without
// closing a borrowed owner. Producers must be joined before the final drain.
func (w *Writer) Flush() {
	if done := w.Pending(); done != nil {
		timer := time.NewTimer(FlushGrace)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
		}
	}
}

// DiagnosticWriter exposes the shared owner through embedding wrappers.
func (w *Writer) DiagnosticWriter() *Writer { return w }

// Write serializes ordinary output without dropping or falsely acknowledging it.
// Like any synchronous shared writer, it waits for the current write to finish.
func (w *Writer) Write(p []byte) (int, error) {
	if w == nil {
		return 0, syscall.EINVAL
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

// TryWrite submits an immutable rendered message without waiting for I/O or a lock.
// It returns nil when busy or disabled, otherwise a delivery-completion signal.
// Completion means the write returned, not that delivery succeeded.
func (w *Writer) TryWrite(message string) <-chan struct{} {
	if w == nil || message == "" || !w.state.TryLock() {
		return nil
	}
	defer w.state.Unlock()
	if w.closed {
		return nil
	}
	if !w.mu.TryLock() {
		return nil
	}
	done := make(chan struct{})
	w.pending = done
	go func() {
		_, _ = io.WriteString(w.w, message)
		w.state.Lock()
		w.pending = nil
		w.mu.Unlock()
		close(done)
		w.state.Unlock()
	}()
	return done
}

// Pending returns a snapshot of the in-flight diagnostic, or nil when idle.
// It is intended for bounded startup flushing and explicit test synchronization.
func (w *Writer) Pending() <-chan struct{} {
	if w == nil {
		return nil
	}
	w.state.Lock()
	defer w.state.Unlock()
	return w.pending
}

// WriteBlocking is the bounded teardown logger's compatibility entry point.
// Its delivery contract is identical to Write; the caller bounds its own wait.
func (w *Writer) WriteBlocking(p []byte) (int, error) {
	return w.Write(p)
}
