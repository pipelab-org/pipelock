// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/filesentry"
)

// fileSentryCloseBackstop converts a deadlocked stop path into a fast, clear
// failure instead of letting it ride out the whole-package deadline. Close
// ends Start in microseconds on a healthy run; this ceiling is generous so
// heavy -race load never trips it.
const fileSentryCloseBackstop = 10 * time.Second

func TestPreferFileSentryRuntimeError(t *testing.T) {
	startupErr := errors.New("bind failed")
	fileSentryErr := errors.New("watch backend failed")

	tests := []struct {
		name     string
		startErr error
		wantErr  error
	}{
		{name: "nil early return", wantErr: fileSentryErr},
		{name: "direct cancellation", startErr: context.Canceled, wantErr: fileSentryErr},
		{name: "wrapped cancellation", startErr: fmt.Errorf("listener startup: %w", context.Canceled), wantErr: fileSentryErr},
		{name: "unrelated startup failure", startErr: startupErr, wantErr: startupErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := preferFileSentryRuntimeError(tt.startErr, fileSentryErr)
			if !errors.Is(got, tt.wantErr) {
				t.Fatalf("preferFileSentryRuntimeError() = %v, want %v", got, tt.wantErr)
			}
		})
	}
}

// TestFileSentryWatcherCloseUnblocksStartWithLiveContext pins the one
// production assumption the gated fake below encodes but cannot validate: that
// Close alone ends Start, and ends it CLEANLY.
//
// Both stop paths depend on it against a live, never-cancelled context.
// `pipelock mcp proxy` calls stop after the wrapped child exits on its own, and
// `pipelock run` calls stop after the proxy returns from Server.Shutdown. In
// neither case has anything cancelled the watcher context, so the fsnotify
// backend closing its Events/Errors channels is the only thing that returns
// Start.
//
// Both failure directions are load-bearing and both are silent in a fake:
// a Start that does not return deadlocks every clean shutdown, and a Start that
// returns non-nil makes every clean run record a file-sentry runtime failure and
// exit nonzero, which is the availability direction that gets a security control
// switched off. The fake decides its own answer here by construction, so this
// case is driven against the real watcher.
func TestFileSentryWatcherCloseUnblocksStartWithLiveContext(t *testing.T) {
	scanContent := false
	cfg := &config.FileSentry{
		Enabled:     true,
		WatchPaths:  []config.WatchPath{{Path: t.TempDir()}},
		ScanContent: &scanContent,
	}
	watcher, err := filesentry.NewWatcher(cfg, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if armErr := watcher.Arm(); armErr != nil {
		t.Fatalf("Arm: %v", armErr)
	}

	// The context stays live until cleanup; Close alone must unblock Start.
	done := runJoined(t, context.Background(), watcher.Start, func() { _ = watcher.Close() })

	if closeErr := watcher.Close(); closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}

	select {
	case startErr := <-done:
		if startErr != nil {
			t.Fatalf("Start after Close on a live context = %v, want nil; a non-nil return here reports a file sentry runtime failure on every clean shutdown", startErr)
		}
	case <-time.After(fileSentryCloseBackstop):
		t.Fatalf("Start did not return within %s of Close on a live context; the stop path deadlocks on every clean shutdown", fileSentryCloseBackstop)
	}
}

// gatedFileSentryWatcher lets runtime tests release a backend failure only
// after the production path has started the watcher. It avoids timing-based
// tests while still exercising the asynchronous lifecycle boundary.
type gatedFileSentryWatcher struct {
	err     error
	started chan struct{}
	release chan struct{}
	stopped chan struct{}

	findings  chan filesentry.Finding
	overflow  chan filesentry.Finding
	closeOnce sync.Once
}

func newGatedFileSentryWatcher(err error) *gatedFileSentryWatcher {
	return &gatedFileSentryWatcher{
		err:      err,
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		stopped:  make(chan struct{}),
		findings: make(chan filesentry.Finding),
		overflow: make(chan filesentry.Finding),
	}
}

func (w *gatedFileSentryWatcher) Arm() error { return nil }

func (w *gatedFileSentryWatcher) Start(ctx context.Context) error {
	close(w.started)
	select {
	case <-w.release:
		return w.err
	case <-w.stopped:
		return nil
	case <-ctx.Done():
		return nil
	}
}

func (w *gatedFileSentryWatcher) Findings() <-chan filesentry.Finding { return w.findings }

func (w *gatedFileSentryWatcher) OverflowFindings() <-chan filesentry.Finding { return w.overflow }

func (w *gatedFileSentryWatcher) DegradedPaths() []filesentry.DegradedPath { return nil }

func (w *gatedFileSentryWatcher) DegradedPathCount() int { return 0 }

func (w *gatedFileSentryWatcher) Close() error {
	w.closeOnce.Do(func() {
		close(w.stopped)
		close(w.findings)
		close(w.overflow)
	})
	return nil
}

// orphanJoinDeadline bounds how long a test waits, at cleanup, for the
// Execute or Start goroutine it launched to return after being stopped.
const orphanJoinDeadline = 30 * time.Second

// leakedRuns counts launched runs that outlived their join deadline. A leaked
// run can still reach a later test's hook, so hook installs refuse to run.
var leakedRuns atomic.Int64

// runJoined runs fn in a goroutine with a context derived from parent and
// returns its result channel. A cleanup cancels that context, calls stop, and
// waits for fn to return, so a run never outlives its test, even after
// t.Fatal. fn must use the context it is given. Cleanups run last-in
// first-out, so call it after installing hooks and creating temp dirs: the run
// is joined while its own hook and config still exist, and a late run can
// never construct a watcher through the next test's hook.
func runJoined(t *testing.T, parent context.Context, fn func(ctx context.Context) error, stop func()) <-chan error {
	t.Helper()
	return runJoinedWithin(t, orphanJoinDeadline, parent, fn, stop)
}

func runJoinedWithin(tb testing.TB, deadline time.Duration, parent context.Context, fn func(ctx context.Context) error, stop func()) <-chan error {
	tb.Helper()
	ctx, cancel := context.WithCancel(parent)
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- fn(ctx)
	}()
	tb.Cleanup(func() {
		cancel()
		if stop != nil {
			stop()
		}
		select {
		case <-finished:
		case <-time.After(deadline):
			leakedRuns.Add(1)
			buf := make([]byte, 1<<20)
			buf = buf[:goruntime.Stack(buf, true)]
			tb.Errorf("launched run did not return within %s of being cancelled; it is leaking and later hook tests will refuse to run. goroutines:\n%s", deadline, buf)
		}
	})
	return done
}

// requireNoLeakedRuns refuses to replace newFileSentryWatcher while a run
// from an earlier test is still alive, because that run could call the new
// hook. Every test that assigns newFileSentryWatcher must call it first;
// TestFileSentryHookSwapsRequireNoLeakedRuns enforces that.
func requireNoLeakedRuns(tb testing.TB) {
	tb.Helper()
	if n := leakedRuns.Load(); n > 0 {
		tb.Fatalf("%d launched run(s) from an earlier test are still running and could reach this hook", n)
	}
}

func installGatedFileSentryWatcher(t *testing.T, watcher *gatedFileSentryWatcher) {
	t.Helper()
	requireNoLeakedRuns(t)
	old := newFileSentryWatcher
	newFileSentryWatcher = func(*config.FileSentry, filesentry.DLPScanner, filesentry.Lineage, func(error)) (filesentry.Watcher, error) {
		return watcher, nil
	}
	t.Cleanup(func() { newFileSentryWatcher = old })
}

// cleanupRecorder captures cleanups and errors so runJoined itself can be
// tested without failing the enclosing test.
type cleanupRecorder struct {
	testing.TB
	cleanups []func()
	errs     []string
	fatals   []string
}

func (r *cleanupRecorder) Helper()                   {}
func (r *cleanupRecorder) Cleanup(f func())          { r.cleanups = append(r.cleanups, f) }
func (r *cleanupRecorder) Errorf(f string, a ...any) { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }

func (r *cleanupRecorder) Fatalf(f string, a ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(f, a...))
}

func (r *cleanupRecorder) runCleanups() {
	for i := len(r.cleanups) - 1; i >= 0; i-- {
		r.cleanups[i]()
	}
}

// runJoined must cancel the run, not merely wait for it: a run that only stops
// on its context has to return at cleanup with context.Canceled.
func TestRunJoinedCancelsBeforeJoining(t *testing.T) {
	parent, release := context.WithCancel(context.Background())
	defer release() // frees the run if runJoined failed to cancel it
	before := leakedRuns.Load()
	t.Cleanup(func() { leakedRuns.Store(before) })

	rec := &cleanupRecorder{TB: t}
	observed := make(chan error, 1)
	done := runJoinedWithin(rec, 2*time.Second, parent, func(ctx context.Context) error {
		<-ctx.Done()
		observed <- ctx.Err()
		return ctx.Err()
	}, nil)

	select {
	case <-done:
		t.Fatal("positive control: run returned before cleanup")
	default:
	}
	rec.runCleanups()
	if len(rec.errs) != 0 {
		t.Fatalf("cleanup did not stop the run: %v", rec.errs[0][:min(len(rec.errs[0]), 200)])
	}
	select {
	case err := <-observed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run saw %v, want context.Canceled", err)
		}
	default:
		t.Fatal("cleanup returned but the run never observed cancellation")
	}
	if got := leakedRuns.Load(); got != before {
		t.Fatalf("leakedRuns = %d, want %d", got, before)
	}
}

// A run that ignores cancellation must fail the test loudly and mark the
// package so later hook installs refuse to run.
func TestRunJoinedReportsLeakedRun(t *testing.T) {
	block, unblock := context.WithCancel(context.Background())
	defer unblock()
	before := leakedRuns.Load()
	t.Cleanup(func() { leakedRuns.Store(before) })

	rec := &cleanupRecorder{TB: t}
	done := runJoinedWithin(rec, 50*time.Millisecond, context.Background(), func(context.Context) error {
		<-block.Done()
		return nil
	}, nil)
	defer func() {
		unblock()
		select {
		case <-done:
		case <-time.After(orphanJoinDeadline):
			t.Error("released run did not return")
		}
	}()
	rec.runCleanups()
	if len(rec.errs) != 1 || !strings.Contains(rec.errs[0], "did not return") || !strings.Contains(rec.errs[0], "goroutine ") {
		t.Fatalf("leak report = %q, want one error with goroutine stacks", rec.errs)
	}
	if leakedRuns.Load() != before+1 {
		t.Fatal("leaked run was not counted")
	}
}

// After a leak, hook installs must refuse; with no leak they must proceed.
func TestRequireNoLeakedRunsRefusesAfterLeak(t *testing.T) {
	before := leakedRuns.Load()
	t.Cleanup(func() { leakedRuns.Store(before) })

	leakedRuns.Store(0)
	clean := &cleanupRecorder{TB: t}
	requireNoLeakedRuns(clean)
	if len(clean.fatals) != 0 {
		t.Fatalf("positive control: refused with no leak: %v", clean.fatals)
	}

	leakedRuns.Store(1)
	leaked := &cleanupRecorder{TB: t}
	requireNoLeakedRuns(leaked)
	if len(leaked.fatals) != 1 || !strings.Contains(leaked.fatals[0], "still running") {
		t.Fatalf("hook install after a leak was not refused: %v", leaked.fatals)
	}
}

// Every function in this package's tests that assigns newFileSentryWatcher
// must call requireNoLeakedRuns before the assignment.
func TestFileSentryHookSwapsRequireNoLeakedRuns(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	swaps := 0
	for _, name := range files {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			guardAt, swapAt := token.NoPos, token.NoPos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "requireNoLeakedRuns" && !guardAt.IsValid() {
						guardAt = n.Pos()
					}
				case *ast.AssignStmt:
					for _, lhs := range n.Lhs {
						if id, ok := lhs.(*ast.Ident); ok && id.Name == "newFileSentryWatcher" && !swapAt.IsValid() {
							swapAt = n.Pos()
						}
					}
				}
				return true
			})
			if !swapAt.IsValid() {
				continue
			}
			swaps++
			if !guardAt.IsValid() || guardAt > swapAt {
				t.Errorf("%s: %s assigns newFileSentryWatcher without calling requireNoLeakedRuns first", fset.Position(swapAt), fn.Name.Name)
			}
		}
	}
	if swaps < 3 {
		t.Fatalf("found %d hook swaps, want at least 3; the scan is not seeing them", swaps)
	}
}
