// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diaglog

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type gatedWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
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

func TestWriter_WedgedDiagnosticBoundsWorkAndDoesNotHoldOrdinaryOutput(t *testing.T) {
	sink := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	w := New(sink)
	done := w.Emit("diagnostic")
	defer func() { close(sink.release); awaitDiagnostic(t, done) }()
	select {
	case <-sink.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("diagnostic never entered sink")
	}
	completed := make(chan struct{})
	go func() {
		defer close(completed)
		for range 10000 {
			if w.Emit("discard while wedged") != nil {
				t.Error("wedged writer admitted another diagnostic")
				return
			}
			if n, err := w.Write([]byte("ordinary output")); err != nil || n != len("ordinary output") {
				t.Errorf("best-effort write=%d,%v", n, err)
				return
			}
		}
	}()
	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("optional I/O stalled a later log or submission")
	}
	if w.Pending() != done {
		t.Fatal("in-flight writer ownership changed")
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
	var nilWriter *Writer
	if New(nil) != nil || nilWriter.Emit("ignored") != nil || nilWriter.Pending() != nil {
		t.Fatal("nil sink was not inert")
	}
	if n, err := nilWriter.Write([]byte("ignored")); n != 7 || err != nil {
		t.Fatalf("nil write=%d,%v", n, err)
	}
}
