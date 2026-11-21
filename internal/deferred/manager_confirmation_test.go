// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
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

type resolutionWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (ctx *resolutionWaitContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

func TestManagerConfirmedHoldDeadlineAfterSiblingWait(t *testing.T) {
	base, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
	defer cancel()
	manager := NewManager(Config{Enabled: true, Timeout: time.Minute})
	entered, release := make(chan struct{}), make(chan struct{})
	resolved := make(chan Resolution, 3)
	parent := HeldAction{
		DeferID: "parent", Authority: AuthoritySnapshot{SessionID: "session"},
		ConfirmHold:       func(context.Context, HeldAction) error { return nil },
		ConfirmResolution: func(context.Context, Resolution) error { return nil },
		Resolve:           func(res Resolution) { resolved <- res },
	}
	if err := manager.HoldContext(base, parent); err != nil {
		t.Fatal(err)
	}
	child := parent
	child.DeferID = "child"
	child.ConfirmHold = func(ctx context.Context, _ HeldAction) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	childDone := make(chan error, 1)
	go func() { childDone <- manager.HoldContext(base, child) }()
	select {
	case <-entered:
	case <-base.Done():
		t.Fatal("child never began confirmation")
	}
	ctx := &resolutionWaitContext{Context: base, waiting: make(chan struct{})}
	parentDone := make(chan error, 1)
	go func() { parentDone <- manager.ResolveContext(ctx, parent.DeferID, config.ActionAllow, SourceApproval) }()
	select {
	case <-ctx.waiting:
	case <-base.Done():
		t.Fatal("approval never waited for the sibling")
	}
	manager.mu.Lock()
	manager.holds[parent.DeferID].Deadline = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	close(release)
	if err := <-childDone; err != nil {
		t.Fatal(err)
	}
	if err := <-parentDone; err != nil {
		t.Fatal(err)
	}
	want := map[string]string{parent.DeferID: SourceTimeout, child.DeferID: SourceCascade}
	for range 2 {
		select {
		case res := <-resolved:
			if source, ok := want[res.DeferID]; !ok || res.FinalDecision != config.ActionBlock || res.ResolutionSource != source {
				t.Fatalf("unexpected resolution %+v; outstanding %v", res, want)
			}
			delete(want, res.DeferID)
		case <-base.Done():
			t.Fatalf("missing resolutions: %v", want)
		}
	}
	select {
	case res := <-resolved:
		t.Fatalf("duplicate resolution: %+v", res)
	default:
	}
}

func TestManagerExpiredConfirmedHoldPreservesExplicitBlock(t *testing.T) {
	manager := NewManager(Config{Enabled: true, Timeout: time.Minute})
	result := make(chan Resolution, 1)
	action := HeldAction{
		DeferID:           "expired",
		ConfirmHold:       func(context.Context, HeldAction) error { return nil },
		ConfirmResolution: func(context.Context, Resolution) error { return nil },
		Resolve:           func(res Resolution) { result <- res },
	}
	if err := manager.HoldContext(t.Context(), action); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.holds[action.DeferID].Deadline = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	if err := manager.ResolveContext(t.Context(), action.DeferID, config.ActionBlock, SourceKillSwitch); err != nil {
		t.Fatal(err)
	}
	if res := <-result; res.FinalDecision != config.ActionBlock || res.ResolutionSource != SourceKillSwitch {
		t.Fatalf("resolution = %+v", res)
	}
}
