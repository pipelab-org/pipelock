// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package licenseclocktest provides a controllable license clock for tests.
package licenseclocktest

import (
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/edition/internal/clockhook"
)

// WallOffset is how far behind wall time tests start a Fake. Any enforcement
// path that reads the wall clock instead of the license clock is then a day
// off, so the test fails instead of passing by coincidence.
const WallOffset = 24 * time.Hour

// Fake holds license time still until the test advances it.
type Fake struct {
	mu     sync.Mutex
	now    time.Time
	timers []*timer
}

type timer struct {
	deadline time.Time
	fn       func()
	stopped  bool
}

type handle struct {
	f *Fake
	t *timer
}

// Install sets a Fake starting at start (truncated to whole seconds, like
// license deadlines) as the license clock until the test ends. The clock is
// process-global: callers must not use t.Parallel.
func Install(t *testing.T, start time.Time) *Fake {
	t.Helper()
	if !testing.Testing() {
		panic("licenseclocktest: Install called outside a test binary")
	}
	f := &Fake{now: time.Unix(start.Unix(), 0)}
	t.Cleanup(clockhook.SetLicenseClock(&edition.LicenseClock{Now: f.Now, AfterFunc: f.AfterFunc}))
	return f
}

// Now returns the fake time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// AfterFunc registers fn to run when Advance moves time to or past now+d.
func (f *Fake) AfterFunc(d time.Duration, fn func()) edition.LicenseTimer {
	f.mu.Lock()
	defer f.mu.Unlock()
	tm := &timer{deadline: f.now.Add(d), fn: fn}
	f.timers = append(f.timers, tm)
	return &handle{f: f, t: tm}
}

// Pending reports how many timers are armed and not yet fired or stopped.
func (f *Fake) Pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, tm := range f.timers {
		if !tm.stopped {
			n++
		}
	}
	return n
}

func (h *handle) Stop() bool {
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	was := !h.t.stopped
	h.t.stopped = true
	return was
}

// Advance moves time forward and runs every live timer that is now due,
// outside the lock. It returns how many timers fired.
func (f *Fake) Advance(d time.Duration) int {
	f.mu.Lock()
	f.now = f.now.Add(d)
	var due []func()
	for _, tm := range f.timers {
		if !tm.stopped && !tm.deadline.After(f.now) {
			tm.stopped = true
			due = append(due, tm.fn)
		}
	}
	f.mu.Unlock()
	for _, fn := range due {
		fn()
	}
	return len(due)
}
