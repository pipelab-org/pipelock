// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/diaglog"
)

type taintRuntimeWriter struct {
	output  syncBuffer
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *taintRuntimeWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.output.Write(p)
}

func TestMCPTaintDiagnostics_BlockedLogDoesNotHoldReload(t *testing.T) {
	w := &taintRuntimeWriter{entered: make(chan struct{}), release: make(chan struct{})}
	// Isolate installed bundles: their pre-existing version warnings are ordinary
	// output, which must retain its synchronous behavior even on a wedged sink.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\nrules:\n  rules_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := newTestServer(t, func(opts *ServerOpts) { opts.ConfigFile = cfgPath })
	s.runtimeMode = config.RuntimeForwardWithMCPListener
	probe := &reloadDiagnosticProbe{Writer: diaglog.New(w), t: t, lock: &s.reloadMu, ordinary: make(chan struct{})}
	s.opts.Stderr = probe
	next, _ := s.proxy.CurrentConfig().ResolveRuntime(config.RuntimeResolveOpts{Mode: s.runtimeMode})
	next.KillSwitch.Enabled = true

	done := make(chan error, 1)
	active := true
	released := false
	go func() { done <- s.Reload(next) }()
	defer func() {
		if !released {
			close(w.release)
		}
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
	// An existing ordinary reload warning must wait for a truly stalled stderr,
	// just as the synchronous writer did before optional diagnostics existed.
	next = s.proxy.CurrentConfig().Clone()
	next.MetricsListen = "127.0.0.1:0"
	s.lastReloadAt = time.Time{}
	active = true
	go func() { done <- s.Reload(next) }()
	select {
	case <-probe.ordinary:
	case <-time.After(2 * time.Second):
		t.Fatal("second reload did not attempt its ordinary warning")
	}
	select {
	case err := <-done:
		active = false
		t.Fatalf("ordinary reload warning falsely completed while sink stalled: %v", err)
	default:
	}
	close(w.release)
	released = true
	select {
	case err := <-done:
		active = false
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not resume after sink recovered")
	}

	if !w.output.contains("metrics_listen changed") {
		t.Fatalf("ordinary reload warning lost: %s", w.output.String())
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
	t        *testing.T
	lock     *sync.Mutex
	ordinary chan struct{}
	once     sync.Once
}

func (w *reloadDiagnosticProbe) DiagnosticWriter() *diaglog.Writer {
	if !w.lock.TryLock() {
		w.t.Error("diagnostic submitted while reloadMu is held")
	} else {
		w.lock.Unlock()
	}
	return w.Writer
}

func (w *reloadDiagnosticProbe) Write(p []byte) (int, error) {
	w.once.Do(func() { w.t.Logf("ordinary reload write: %s", p); close(w.ordinary) })
	return w.Writer.Write(p)
}

// The owner survives config reloads and is drained when Start returns. A caller
// may read its ordinary bytes.Buffer only after that return, without a mutex.
func TestMCPTaintDiagnostics_ShutdownFencesReloadPlainBuffer(t *testing.T) {
	for _, source := range []string{"startup", "reload"} {
		t.Run(source, func(t *testing.T) {
			var output bytes.Buffer
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) }))
			defer upstream.Close()
			opts := func(o *ServerOpts) {
				o.Stderr = &output
				o.Stdout = io.Discard
				o.Listen = serverTestEphemeralListen
				o.ListenChanged = true
				o.MCPListen = serverTestEphemeralListen
				o.MCPUpstream = upstream.URL
				o.allowEphemeralListenersForTesting = true
			}
			s, _ := newTestServer(t, opts)
			if source == "reload" {
				for range 16 {
					s.lastReloadAt = time.Time{}
					if err := s.Reload(s.proxy.CurrentConfig().Clone()); err != nil {
						t.Fatal(err)
					}
				}
			}
			assertTaintShutdownPlainBuffer(t, s, &output)
		})
	}
}

func assertTaintShutdownPlainBuffer(t *testing.T, s *Server, output *bytes.Buffer) {
	t.Helper()
	owner := diaglog.New(s.opts.Stderr)
	if diaglog.New(s.opts.Stderr) != owner {
		t.Fatal("shared owner lookup split ownership")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	waitForServerCancel(t, s)
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server shutdown stalled")
	}
	// Read immediately after Start returns, without a Pending wait or owner lock.
	if got := output.String(); !strings.Contains(got, "taint.mcp_listener:") {
		t.Fatalf("diagnostic missing: %q", got)
	}
	if owner.TryWrite("after server return") != nil {
		t.Fatal("server return left diagnostic admission open")
	}
	if owner.Pending() != nil {
		t.Fatal("server return left a healthy diagnostic in flight")
	}
}

func TestMCPTaintDiagnostics_CleanupDrainsOptionalWrite(t *testing.T) {
	s, _ := newTestServer(t, nil)
	originalFinish := s.finishDiagnostics
	originalFinish()
	sink := &taintRuntimeWriter{entered: make(chan struct{}), release: make(chan struct{})}
	owner, finish := diaglog.Scope(sink)
	s.opts.Stderr = owner
	s.finishDiagnostics = finish
	pending := owner.TryWrite("final operator diagnostic")
	<-sink.entered
	finished := make(chan struct{})
	go func() { s.cleanup(); close(finished) }()
	defer func() {
		close(sink.release)
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("cleanup did not settle")
		}
		if pending != nil {
			<-pending
		}
	}()
	select {
	case <-finished:
		t.Fatal("server cleanup returned before the healthy diagnostic settled")
	case <-time.After(30 * time.Millisecond):
	}
}
