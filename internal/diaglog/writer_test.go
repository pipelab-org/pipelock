// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diaglog

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type gatedWriter struct {
	output  bytes.Buffer
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.output.Write(p)
}

func awaitDiagnostic(t *testing.T, done <-chan struct{}) {
	t.Helper()
	if done == nil {
		t.Fatal("diagnostic was not admitted")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("diagnostic did not finish")
	}
}

// Only optional diagnostics may be skipped. Ordinary writes keep the synchronous
// delivery contract, even while an optional write owns the sink.
func TestWriter_WedgedDiagnosticBoundsWorkAndPreservesOrdinaryOutput(t *testing.T) {
	sink := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	w := New(sink)
	done := w.Emit("diagnostic")
	released := false
	defer func() {
		if !released {
			close(sink.release)
		}
		awaitDiagnostic(t, done)
	}()
	<-sink.entered
	for range 10000 {
		if w.Emit("discard while wedged") != nil {
			t.Fatal("wedged writer admitted another diagnostic")
		}
	}
	if w.Pending() != done {
		t.Fatal("in-flight writer ownership changed")
	}
	completed := make(chan struct{})
	go func() {
		defer close(completed)
		if n, err := w.Write([]byte("ordinary output")); n != len("ordinary output") || err != nil {
			t.Errorf("ordinary write=%d,%v", n, err)
		}
	}()
	select {
	case <-completed:
		t.Error("ordinary write falsely acknowledged before sink was released")
	case <-time.After(50 * time.Millisecond):
	}
	close(sink.release)
	released = true
	awaitDiagnostic(t, completed)
	awaitDiagnostic(t, done)
	if got := sink.output.String(); got != "diagnosticordinary output" {
		t.Fatalf("ordinary output lost: %q", got)
	}
}

func TestWriter_NilOrdinaryWriteIsNotAcknowledged(t *testing.T) {
	var w *Writer
	if n, err := w.Write([]byte("ordinary")); n != 0 || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil ordinary write=%d,%v, want 0, EINVAL", n, err)
	}
}

func TestWriter_BusyOrdinarySinkDoesNotHoldDiagnosticAdmission(t *testing.T) {
	for _, kind := range []string{"sink", "state"} {
		t.Run(kind, func(t *testing.T) {
			sink := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}
			w := New(sink)
			var ordinaryDone chan struct{}
			if kind == "sink" {
				ordinaryDone = make(chan struct{})
				go func() { defer close(ordinaryDone); _, _ = w.Write([]byte("ordinary")) }()
				<-sink.entered
			} else {
				w.state.Lock()
			}
			submitted := make(chan (<-chan struct{}), 1)
			go func() { submitted <- w.Emit("optional") }()
			defer func() {
				if kind == "state" {
					w.state.Unlock()
				}
				close(sink.release)
				if ordinaryDone != nil {
					awaitDiagnostic(t, ordinaryDone)
				}
				// If the tested submission timed out, cleanup must still settle it.
				if done := w.Pending(); done != nil {
					awaitDiagnostic(t, done)
				}
			}()
			select {
			case done := <-submitted:
				if done != nil {
					t.Error("busy writer admitted a diagnostic")
				}
			case <-time.After(200 * time.Millisecond):
				t.Error("busy writer stalled diagnostic admission")
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("sink unavailable") }
func TestWriter_HealthyFailedNilAndSharedOwner(t *testing.T) {
	var out bytes.Buffer
	w := New(&out)
	if New(w) != w {
		t.Fatal("new wrapper split shared ownership")
	}
	if _, err := io.WriteString(w, "ordinary\n"); err != nil {
		t.Fatal(err)
	}
	awaitDiagnostic(t, w.Emit("optional\n"))
	if out.String() != "ordinary\noptional\n" {
		t.Fatal(out.String())
	}
	if n, err := w.WriteBlocking([]byte("teardown")); n != 8 || err != nil {
		t.Fatalf("blocking write=%d,%v", n, err)
	}
	if w.Pending() != nil {
		t.Fatal("idle drainer retained")
	}
	if w.Emit("") != nil {
		t.Fatal("empty diagnostic admitted")
	}
	failed := New(failingWriter{})
	awaitDiagnostic(t, failed.Emit("failed"))
	awaitDiagnostic(t, failed.Emit("retry"))
	if _, err := failed.Write([]byte("failed")); err == nil || !strings.Contains(err.Error(), "sink unavailable") {
		t.Fatalf("ordinary write error lost: %v", err)
	}
	if _, err := failed.WriteBlocking([]byte("failed")); err == nil {
		t.Fatal("blocking write lost error")
	}
	var nilWriter *Writer
	if n, err := nilWriter.WriteBlocking([]byte("ignored")); n != 0 || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil blocking write=%d,%v", n, err)
	}
	if New(nil) != nil || nilWriter.Emit("ignored") != nil || nilWriter.Pending() != nil {
		t.Fatal("nil sink was not inert")
	}
	if n, err := nilWriter.Write([]byte("ignored")); n != 0 || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil write=%d,%v", n, err)
	}
}
