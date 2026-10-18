// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package edition

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/edition/internal/clockhook"
)

func TestSetLicenseClock(t *testing.T) {
	stub := func(time.Duration, func()) LicenseTimer { return time.NewTimer(time.Hour) }
	cases := []struct {
		name      string
		clock     *LicenseClock
		wantPanic bool
	}{
		{name: "nil restores wall clock", clock: nil},
		{name: "complete clock", clock: &LicenseClock{Now: time.Now, AfterFunc: stub}},
		{name: "nil Now", clock: &LicenseClock{AfterFunc: stub}, wantPanic: true},
		{name: "nil AfterFunc", clock: &LicenseClock{Now: time.Now}, wantPanic: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := licenseClock.Load()
			defer func() {
				r := recover()
				if (r != nil) != tc.wantPanic {
					t.Fatalf("panic = %v, wantPanic %v", r, tc.wantPanic)
				}
				if tc.wantPanic && licenseClock.Load() != before {
					t.Fatal("rejected clock was installed")
				}
			}()
			restore := setLicenseClock(tc.clock)
			defer restore()
			got := CurrentLicenseClock()
			if got.Now == nil || got.AfterFunc == nil {
				t.Fatal("installed clock has a nil func")
			}
			if tc.clock == nil && licenseClock.Load() != wallLicenseClock {
				t.Fatal("nil did not install the wall clock")
			}
		})
	}
	if licenseClock.Load() != wallLicenseClock {
		t.Fatal("restore did not return to the wall clock")
	}
}

// The default license clock must be the wall clock with a real timer: a
// default that lags would let paid profiles outlive their license.
func TestDefaultLicenseClockIsWallClock(t *testing.T) {
	c := CurrentLicenseClock()
	if licenseClock.Load() != wallLicenseClock {
		t.Fatal("default license clock is not the wall clock")
	}
	before := time.Now()
	now := c.Now()
	after := time.Now()
	if now.Before(before) || now.After(after) {
		t.Fatalf("default license clock reading %s is outside wall-clock bounds [%s, %s]", now, before, after)
	}
	const delay = 50 * time.Millisecond
	firedAt := make(chan time.Time, 1)
	start := time.Now()
	timer := c.AfterFunc(delay, func() { firedAt <- time.Now() })
	defer timer.Stop()
	if _, ok := timer.(*time.Timer); !ok {
		t.Fatalf("default AfterFunc returned %T, want *time.Timer", timer)
	}
	select {
	case at := <-firedAt:
		if elapsed := at.Sub(start); elapsed < delay {
			t.Fatalf("default AfterFunc fired after %s, before its %s delay", elapsed, delay)
		}
	case <-time.After(delay + time.Second):
		t.Fatalf("default AfterFunc did not fire within 1s of its %s delay", delay)
	}
}

func TestClockHookInstallsAndRestores(t *testing.T) {
	restoreWall := clockhook.SetLicenseClock(nil)
	if licenseClock.Load() != wallLicenseClock {
		t.Fatal("nil hook did not restore the wall clock")
	}
	restoreWall()
	stub := func(time.Duration, func()) LicenseTimer { return time.NewTimer(time.Hour) }
	fake := &LicenseClock{Now: time.Now, AfterFunc: stub}
	restore := clockhook.SetLicenseClock(fake)
	if licenseClock.Load() != fake {
		t.Fatal("hook did not install the clock")
	}
	restore()
	if licenseClock.Load() != wallLicenseClock {
		t.Fatal("hook restore did not return to the wall clock")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("hook accepted a value that is not a *LicenseClock")
		}
		if licenseClock.Load() != wallLicenseClock {
			t.Fatal("rejected value changed the clock")
		}
	}()
	clockhook.SetLicenseClock("not a clock")
}

func TestCurrentLicenseClockReturnsSnapshot(t *testing.T) {
	clock := CurrentLicenseClock()
	before := clock.Now()
	clock.Now = func() time.Time { return before.Add(-time.Hour) }
	clock.AfterFunc = nil
	current := CurrentLicenseClock()
	if current.AfterFunc == nil || current.Now().Before(before) {
		t.Fatal("changing the returned clock changed the active license clock")
	}
}
