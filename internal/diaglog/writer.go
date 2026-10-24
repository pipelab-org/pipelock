// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package diaglog serializes operator output and bounds optional diagnostic I/O.
package diaglog

import (
	"io"
	"sync"
	"syscall"
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
