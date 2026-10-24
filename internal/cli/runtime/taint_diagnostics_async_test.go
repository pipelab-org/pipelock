// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/diaglog"
)

type taintRuntimeWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *taintRuntimeWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "pipelock: diagnostic:") {
		w.once.Do(func() { close(w.entered) })
		<-w.release
	}
	return len(p), nil
}

func TestMCPTaintDiagnostics_BlockedLogDoesNotHoldReload(t *testing.T) {
	w := &taintRuntimeWriter{entered: make(chan struct{}), release: make(chan struct{})}
	s, _ := newTestServer(t, func(opts *ServerOpts) { opts.Stderr = w })
	s.runtimeMode = config.RuntimeForwardWithMCPListener
	s.opts.Stderr = &reloadDiagnosticProbe{Writer: diaglog.New(s.opts.Stderr), t: t, lock: &s.reloadMu}
	next := s.proxy.CurrentConfig().Clone()
	next.KillSwitch.Enabled = true

	done := make(chan error, 1)
	active := true
	go func() { done <- s.Reload(next) }()
	defer func() {
		close(w.release)
		if active {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("reload cleanup stalled")
			}
		}
		waitRuntimeTaintDiagnostic(t, diaglog.New(s.opts.Stderr))
	}()
	select {
	case err := <-done:
		active = false
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reload held by optional diagnostic")
	}
	select {
	case <-w.entered:
	case <-time.After(4 * time.Second):
		t.Fatal("diagnostic was not submitted")
	}
	if !s.killswitch.IsActive() {
		t.Fatal("reload did not keep kill switch fail-closed")
	}
	if !s.reloadMu.TryLock() {
		t.Fatal("diagnostic I/O still owns reloadMu")
	}
	s.reloadMu.Unlock()
	// A second reload must complete while the first diagnostic is still wedged.
	next = s.proxy.CurrentConfig().Clone()
	next.Logging.IncludeAllowed = !next.Logging.IncludeAllowed
	s.lastReloadAt = time.Time{}
	active = true
	go func() { done <- s.Reload(next) }()
	select {
	case err := <-done:
		active = false
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("next reload held by prior diagnostic")
	}
	if !s.killswitch.IsActive() {
		t.Fatal("second reload weakened kill switch")
	}
}

func waitRuntimeTaintDiagnostic(t *testing.T, w *diaglog.Writer) {
	t.Helper()
	if done := w.Pending(); done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("diagnostic did not finish")
		}
	}
}

// The owner lookup itself must occur after unlock, independent of when the
// diagnostic goroutine happens to run.
type reloadDiagnosticProbe struct {
	*diaglog.Writer
	t    *testing.T
	lock *sync.Mutex
}

func (w *reloadDiagnosticProbe) DiagnosticWriter() *diaglog.Writer {
	if !w.lock.TryLock() {
		w.t.Error("diagnostic submitted while reloadMu is held")
	} else {
		w.lock.Unlock()
	}
	return w.Writer
}
