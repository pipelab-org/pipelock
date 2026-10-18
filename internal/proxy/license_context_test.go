// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/edition/licenseclocktest"
)

func TestAgentLicenseContext(t *testing.T) {
	t.Parallel()
	for _, alreadyRevoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "open", true: "already-revoked"}[alreadyRevoked], func(t *testing.T) {
			done := make(chan struct{})
			if alreadyRevoked {
				close(done)
			}
			ctx, cancel := agentLicenseContext(t.Context(), &edition.ResolvedAgent{LicenseRevoked: done})
			defer cancel()
			if alreadyRevoked && ctx.Err() == nil {
				t.Fatal("already-revoked context must be canceled synchronously")
			}
			if !alreadyRevoked {
				if ctx.Err() != nil {
					t.Fatal("unrevoked entitlement cancelled")
				}
				close(done)
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("revocation did not cancel context")
			}
			if !errors.Is(context.Cause(ctx), errAgentLicenseRevoked) {
				t.Fatalf("wrong cancellation cause: %v", context.Cause(ctx))
			}
		})
	}
	ctx, cancel := agentLicenseContext(t.Context(), &edition.ResolvedAgent{})
	cancel()
	if ctx != t.Context() || ctx.Err() != nil {
		t.Fatal("free profile context changed")
	}
	parent, stop := context.WithCancel(t.Context())
	ctx, cancel = agentLicenseContext(parent, &edition.ResolvedAgent{LicenseRevoked: make(chan struct{})})
	defer cancel()
	stop()
	if !errors.Is(context.Cause(ctx), context.Canceled) {
		t.Fatal("parent cancellation lost")
	}
	ctx, cancel = agentLicenseContext(t.Context(), &edition.ResolvedAgent{LicenseRevoked: make(chan struct{})})
	cancel()
	if !errors.Is(context.Cause(ctx), context.Canceled) {
		t.Fatal("normal completion did not stop watcher")
	}
}

// On the default wall clock, an entitlement whose deadline has already passed
// cancels synchronously. The deadline is in the past, so there is no window to
// race; a default clock that lags wall time by more than ~2s fails here.
func TestAgentLicenseContextExpiredOnWallClock(t *testing.T) {
	t.Parallel()
	ctx, release := agentLicenseContext(t.Context(), &edition.ResolvedAgent{LicenseRevoked: make(chan struct{}), LicenseExpiresAt: time.Now().Add(-2 * time.Second).Unix()})
	defer release()
	if ctx.Err() == nil || !errors.Is(context.Cause(ctx), errAgentLicenseRevoked) {
		t.Fatalf("expired entitlement on the wall clock: err=%v cause=%v, want synchronous license cancellation", ctx.Err(), context.Cause(ctx))
	}
}

// The license clock is process-global, so this test does not run in parallel.
func TestAgentLicenseContextExpiry(t *testing.T) {
	for _, future := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "upcoming"}[future], func(t *testing.T) {
			clk := licenseclocktest.Install(t, time.Now().Add(-licenseclocktest.WallOffset))
			deadline := clk.Now().Add(-time.Second).Unix()
			if future {
				deadline = clk.Now().Add(time.Hour).Unix()
			}
			ctx, release := agentLicenseContext(t.Context(), &edition.ResolvedAgent{LicenseRevoked: make(chan struct{}), LicenseExpiresAt: deadline})
			defer release()
			if !future {
				if ctx.Err() == nil {
					t.Fatal("expired entitlement must cancel synchronously")
				}
			} else {
				if ctx.Err() != nil {
					t.Fatalf("upcoming entitlement cancelled before its deadline: %v", context.Cause(ctx))
				}
				if fired := clk.Advance(time.Hour - time.Second); fired != 0 || ctx.Err() != nil {
					t.Fatalf("expiry fired early: fired=%d err=%v", fired, ctx.Err())
				}
				if fired := clk.Advance(time.Second); fired != 1 {
					t.Fatalf("expiry timers fired at deadline = %d, want 1", fired)
				}
			}
			select {
			case <-ctx.Done():
			default:
				t.Fatal("expiry did not cancel request")
			}
			if !errors.Is(context.Cause(ctx), errAgentLicenseRevoked) {
				t.Fatal(context.Cause(ctx))
			}
		})
	}
}

func TestAgentLicenseContextReleaseStopsExpiry(t *testing.T) {
	clk := licenseclocktest.Install(t, time.Now().Add(-licenseclocktest.WallOffset))
	ctx, release := agentLicenseContext(t.Context(), &edition.ResolvedAgent{
		LicenseRevoked: make(chan struct{}), LicenseExpiresAt: clk.Now().Add(time.Hour).Unix(),
	})
	defer release()
	if clk.Pending() != 1 || ctx.Err() != nil {
		t.Fatal("future entitlement did not arm its timer")
	}
	release()
	if clk.Pending() != 0 || clk.Advance(time.Hour) != 0 {
		t.Fatal("released context retained its expiry timer")
	}
	if !errors.Is(context.Cause(ctx), context.Canceled) {
		t.Fatalf("release cause = %v", context.Cause(ctx))
	}
}

func TestAgentLicenseContextConcurrentLifecycle(t *testing.T) {
	clk := licenseclocktest.Install(t, time.Now().Add(-licenseclocktest.WallOffset))
	revoked := make(chan struct{})
	parent, stop := context.WithCancel(t.Context())
	defer stop()
	ctx, release := agentLicenseContext(parent, &edition.ResolvedAgent{
		LicenseRevoked: revoked, LicenseExpiresAt: clk.Now().Add(time.Hour).Unix(),
	})
	defer release()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, action := range []func(){release, func() { close(revoked) }, func() { clk.Advance(time.Hour) }, stop} {
		wg.Go(func() { <-start; action() })
	}
	close(start)
	wg.Wait()
	if ctx.Err() == nil || clk.Pending() != 0 {
		t.Fatal("concurrent lifecycle left a live context or timer")
	}
	cause := context.Cause(ctx)
	if !errors.Is(cause, context.Canceled) && !errors.Is(cause, errAgentLicenseRevoked) {
		t.Fatalf("unexpected cause: %v", cause)
	}
}
