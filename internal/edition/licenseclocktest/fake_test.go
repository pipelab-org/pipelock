// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package licenseclocktest

import (
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
