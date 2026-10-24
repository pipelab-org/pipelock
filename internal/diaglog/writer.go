// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package diaglog serializes operator output and bounds optional diagnostic I/O.
package diaglog

import (
	"io"
	"sync"
)

// Writer shares one lock for ordinary output and optional diagnostics. Ordinary
// writes remain synchronous unless an optional diagnostic owns the sink: then
// they are dropped, so that optional I/O cannot indirectly stall an operation.
// Diagnostics are best-effort, with one in-flight message and no pending queue.
// A permanently wedged sink retains at most one diagnostic goroutine per Writer.
type Writer struct {
	w       io.Writer
	mu      sync.Mutex
	state   sync.Mutex
	pending chan struct{}
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

// DiagnosticWriter exposes the shared owner through embedding wrappers.
func (w *Writer) DiagnosticWriter() *Writer { return w }

// Write serializes normal output. While optional output is in flight, dropping
// a concurrent log is preferable to letting that diagnostic block its caller.
func (w *Writer) Write(p []byte) (int, error) {
	if w == nil {
		return len(p), nil
	}
	w.state.Lock()
	if w.pending != nil {
		w.state.Unlock()
		return len(p), nil
	}
	w.mu.Lock()
	w.state.Unlock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

// Emit submits an immutable rendered message without waiting for I/O or a lock.
// It returns nil when busy or disabled, otherwise a delivery-completion signal.
// Completion means the write returned, not that delivery succeeded.
func (w *Writer) Emit(message string) <-chan struct{} {
	if w == nil || message == "" || !w.state.TryLock() {
		return nil
	}
	defer w.state.Unlock()
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

// WriteBlocking preserves the existing bounded teardown logger's delivery
// attempt. Only callers that already bound their wait may use this path;
// optional request/refusal/reload diagnostics must use Emit instead.
func (w *Writer) WriteBlocking(p []byte) (int, error) {
	if w == nil {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}
