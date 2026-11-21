// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestManagerConfirmationReservesCapacity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	manager := NewManager(Config{Enabled: true, Timeout: time.Minute, MaxPending: 1})
	entered, release := make(chan struct{}), make(chan struct{})
	resolved := make(chan Resolution, 1)
	action := HeldAction{
		DeferID:   "first",
		Authority: AuthoritySnapshot{SessionID: "session"},
		ConfirmHold: func(ctx context.Context, _ HeldAction) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		ConfirmResolution: func(context.Context, Resolution) error { return nil },
		Resolve:           func(res Resolution) { resolved <- res },
	}
	first := make(chan error, 1)
	go func() { first <- manager.HoldContext(ctx, action) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("hold confirmation never started")
	}

	second := make(chan error, 1)
	go func() {
		if manager.HeldCount() != 0 {
			second <- errors.New("unconfirmed hold was visible")
			return
		}
		second <- manager.HoldContext(ctx, HeldAction{
			DeferID: "second", Authority: action.Authority, Resolve: func(Resolution) {},
		})
	}()
	select {
	case err := <-second:
		if !errors.Is(err, ErrCapacity) {
			t.Fatalf("second hold = %v, want capacity error", err)
		}
	case <-ctx.Done():
		t.Fatal("capacity check waited for receipt confirmation")
	}

	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := manager.ResolveContext(ctx, action.DeferID, config.ActionBlock, SourceKillSwitch); err != nil {
		t.Fatal(err)
	}
	if res := <-resolved; res.FinalDecision != config.ActionBlock || res.ResolutionSource != SourceKillSwitch {
		t.Fatalf("resolution = %+v", res)
	}
}

func TestManagerResolutionConfirmationFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	manager := NewManager(Config{Enabled: true, Timeout: time.Minute, MaxPending: 1})
	writeErr := errors.New("resolution write failed")
	entered, release := make(chan struct{}), make(chan struct{})
	resolved := make(chan Resolution, 1)
	action := HeldAction{
		DeferID:     "first",
		ConfirmHold: func(context.Context, HeldAction) error { return nil },
		ConfirmResolution: func(ctx context.Context, _ Resolution) error {
			close(entered)
			select {
			case <-release:
				return writeErr
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		Resolve: func(res Resolution) { resolved <- res },
	}
	if err := manager.HoldContext(ctx, action); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- manager.ResolveContext(ctx, action.DeferID, config.ActionAllow, SourceApproval) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("resolution confirmation never started")
	}
	duplicate := make(chan error, 1)
	go func() {
		duplicate <- manager.ResolveContext(ctx, action.DeferID, config.ActionBlock, SourceKillSwitch)
	}()
	select {
	case err := <-duplicate:
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("duplicate resolution = %v, want not found", err)
		}
	case <-ctx.Done():
		t.Fatal("duplicate resolution waited for receipt confirmation")
	}
	close(release)
	if err := <-done; !errors.Is(err, writeErr) {
		t.Fatalf("resolution = %v, want receipt write error", err)
	}
	if res := <-resolved; res.FinalDecision != config.ActionBlock || res.Reason != ReasonReceiptNotWritten {
		t.Fatalf("resolution = %+v", res)
	}
	if err := manager.Hold(HeldAction{DeferID: "next", Resolve: func(Resolution) {}}); err != nil {
		t.Fatalf("hold capacity leaked: %v", err)
	}
	manager.ResolveAll(config.ActionBlock, SourceCancel)
}
