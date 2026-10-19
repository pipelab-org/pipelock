// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package edition

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/edition/internal/clockhook"
)

// LicenseTimer is the subset of *time.Timer that license expiry needs.
type LicenseTimer interface {
	Stop() bool
}

// LicenseClock supplies the time source for runtime license expiry
// enforcement: named-profile lookup (enterprise registry), the per-connection
// expiry timer (proxy), and the server's runtime expiry watchdog that ends the
// licensed runtime. Production uses the wall clock. Expiry warnings, status,
// dashboard and doctor output report against the wall clock and do not read
// it.
type LicenseClock struct {
	Now       func() time.Time
	AfterFunc func(d time.Duration, f func()) LicenseTimer
}

var wallLicenseClock = &LicenseClock{
	Now:       time.Now,
	AfterFunc: func(d time.Duration, f func()) LicenseTimer { return time.AfterFunc(d, f) },
}

var licenseClock atomic.Pointer[LicenseClock]

func init() {
	licenseClock.Store(wallLicenseClock)
	clockhook.SetLicenseClock = func(clock any) func() {
		if clock == nil {
			return setLicenseClock(nil)
		}
		c, ok := clock.(*LicenseClock)
		if !ok {
			panic(fmt.Sprintf("edition: license clock override has type %T, want *LicenseClock", clock))
		}
		return setLicenseClock(c)
	}
}

// CurrentLicenseClock returns a snapshot of the active license clock.
// Changing the returned value does not change the active clock.
func CurrentLicenseClock() LicenseClock { return *licenseClock.Load() }

// setLicenseClock replaces the license clock and returns a restore function.
// nil restores the wall clock; a clock with a nil Now or AfterFunc panics. It
// is reachable only from this package and, through internal/clockhook, from
// licenseclocktest, which production binaries never link. The clock is
// process-global, so a test that sets it must not run in parallel with other
// license tests.
func setLicenseClock(c *LicenseClock) (restore func()) {
	if c == nil {
		c = wallLicenseClock
	}
	if c.Now == nil || c.AfterFunc == nil {
		panic("edition: license clock needs both Now and AfterFunc")
	}
	prev := licenseClock.Swap(c)
	return func() { licenseClock.Store(prev) }
}
