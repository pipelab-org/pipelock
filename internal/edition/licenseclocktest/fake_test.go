// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package licenseclocktest

import (
	"slices"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/edition"
)

func TestFakeTimers(t *testing.T) {
	start := time.Now().Add(-WallOffset)
	f := Install(t, start)
	if !f.Now().Equal(time.Unix(start.Unix(), 0)) {
		t.Fatal("clock did not truncate to license seconds")
	}
	if !edition.CurrentLicenseClock().Now().Equal(f.Now()) {
		t.Fatal("fake clock was not installed")
	}
	fired := 0
	first := f.AfterFunc(time.Second, func() {
		fired++
		// Callbacks may read the clock and arm another timer without deadlocking.
		f.AfterFunc(time.Second, func() { fired++ })
	})
	stopped := f.AfterFunc(time.Second, func() { t.Error("stopped callback ran") })
	if !stopped.Stop() || stopped.Stop() {
		t.Fatal("Stop did not report the active-to-stopped transition")
	}
	if f.Pending() != 1 {
		t.Fatal("stopped timer remains pending")
	}
	if f.Advance(0) != 0 || fired != 0 {
		t.Fatal("timer fired early")
	}
	if f.Advance(time.Second) != 1 || fired != 1 {
		t.Fatal("first timer did not fire at its deadline")
	}
	if first.Stop() {
		t.Fatal("fired timer reported active")
	}
	if f.Pending() != 1 {
		t.Fatal("callback did not arm the second timer")
	}
	if f.Advance(time.Second) != 1 || fired != 2 {
		t.Fatal("second timer did not fire")
	}
	if f.Pending() != 0 || f.Advance(time.Hour) != 0 {
		t.Fatal("timer fired more than once")
	}
}

func TestAdvanceRetiresTimersInDeadlineOrder(t *testing.T) {
	f := Install(t, time.Now().Add(-WallOffset))
	var fired []string
	f.AfterFunc(3*time.Second, func() { fired = append(fired, "late") })
	f.AfterFunc(time.Second, func() { fired = append(fired, "early") })
	f.AfterFunc(time.Second, func() { fired = append(fired, "same-deadline") })
	stopped := f.AfterFunc(time.Second, func() { t.Error("stopped callback ran") })
	if !stopped.Stop() {
		t.Fatal("timer was not active")
	}
	future := f.AfterFunc(4*time.Second, func() { fired = append(fired, "future") })
	storage := f.timers
	if got := f.Advance(3 * time.Second); got != 3 {
		t.Fatalf("fired %d timers, want 3", got)
	}
	if want := []string{"early", "same-deadline", "late"}; !slices.Equal(fired, want) {
		t.Fatalf("callback order = %v, want %v", fired, want)
	}
	if len(f.timers) != 1 || f.Pending() != 1 {
		t.Fatal("retired timers retained or future timer lost")
	}
	for _, tm := range storage[1:] {
		if tm != nil {
			t.Fatal("discarded storage still retains a timer")
		}
	}
	if !future.Stop() || f.Advance(0) != 0 || len(f.timers) != 0 {
		t.Fatal("stopped future timer was not retired")
	}
	if f.Advance(time.Hour) != 0 || len(fired) != 3 {
		t.Fatal("retired callback ran again")
	}
}
