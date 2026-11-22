// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
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
	if err := manager.Hold(HeldAction{DeferID: "next", Resolve: func(Resolution) {}}); !errors.Is(err, ErrCapacity) {
		t.Errorf("hold during settlement = %v, want capacity error", err)
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

func TestManagerRejectsUnusableConfirmation(t *testing.T) {
	writeErr := errors.New("hold write failed")
	action := HeldAction{
		DeferID:           "hold",
		ConfirmHold:       func(context.Context, HeldAction) error { return writeErr },
		ConfirmResolution: func(context.Context, Resolution) error { return nil },
		Resolve:           func(Resolution) { t.Error("unconfirmed hold resolved") },
	}
	manager := NewManager(Config{Enabled: true, MaxPending: 1})
	partial := action
	partial.ConfirmResolution = nil
	if err := manager.Hold(partial); err == nil {
		t.Fatal("accepted a hold without resolution confirmation")
	}
	journal := NewManager(Config{Enabled: true, JournalPath: t.TempDir() + "/holds.jsonl"})
	if err := journal.Hold(action); err == nil {
		t.Fatal("accepted receipt confirmation with journal enabled")
	}
	if err := manager.Hold(action); !errors.Is(err, writeErr) || manager.HeldCount() != 0 {
		t.Fatalf("failed write left a published hold: %v", err)
	}
	action.ConfirmHold = func(context.Context, HeldAction) error { return nil }
	action.Resolve = func(Resolution) {}
	if err := manager.Hold(action); err != nil {
		t.Fatalf("failed write retained the reservation: %v", err)
	}
	manager.ResolveAll(config.ActionBlock, SourceCancel)
}

func TestManagerPendingConfirmationCancellation(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
	defer stop()
	manager := NewManager(Config{Enabled: true, Timeout: time.Minute})
	parent := HeldAction{DeferID: "parent", Authority: AuthoritySnapshot{SessionID: "session"}, Resolve: func(Resolution) {}}
	if err := manager.Hold(parent); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
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
	child.ConfirmResolution = func(context.Context, Resolution) error { return nil }
	held := make(chan error, 1)
	go func() { held <- manager.HoldContext(ctx, child) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("child did not enter confirmation")
	}
	if snapshot := manager.Snapshot(); len(snapshot) != 1 || snapshot[0].DeferID != parent.DeferID {
		t.Fatalf("pending child appeared in snapshot: %+v", snapshot)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	sibling := parent
	sibling.DeferID = "sibling"
	sibling.SizeBytes = 8
	if err := manager.HoldContext(cancelled, sibling); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting sibling returned %v", err)
	}
	for _, id := range []string{parent.DeferID, child.DeferID} {
		if err := manager.ResolveContext(cancelled, id, config.ActionAllow, SourceApproval); !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting resolution for %s returned %v", id, err)
		}
	}
	if err := manager.Resolve(parent.DeferID, config.ActionBlock, SourceKillSwitch); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if err := manager.Hold(sibling); err != nil {
		t.Fatalf("cancelled reservation was retained: %v", err)
	}
	manager.ResolveAll(config.ActionBlock, SourceCancel)
}

func TestManagerLateRefusalOfConfirmedApproval(t *testing.T) {
	manager := NewManager(Config{Enabled: true, Timeout: time.Minute})
	var recorded []Resolution
	var delivered Resolution
	action := HeldAction{
		DeferID:     "hold",
		ConfirmHold: func(context.Context, HeldAction) error { return nil },
		ConfirmResolution: func(_ context.Context, res Resolution) error {
			recorded = append(recorded, res)
			return nil
		},
		ResolveWithReleaseRefusal: func(_ Resolution, refuse func(string) Resolution) {
			delivered = refuse("transport declined release")
		},
	}
	if err := manager.Hold(action); err != nil {
		t.Fatal(err)
	}
	if err := manager.Resolve(action.DeferID, config.ActionAllow, SourceApproval); err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 || recorded[0].FinalDecision != config.ActionAllow ||
		delivered.FinalDecision != config.ActionBlock || delivered.ResolutionSource != SourceCancel ||
		delivered.Reason != "transport declined release" {
		t.Fatalf("recorded = %+v; delivered = %+v", recorded, delivered)
	}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, SourceTimeout},
		{context.Canceled, SourceCancel},
	} {
		if got := HoldFailureSource(tc.err); got != tc.want {
			t.Errorf("source for %v = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestManagerBulkResolutionIncludesWaitingHolds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		resolve func(*Manager)
	}{
		{"kill switch", func(m *Manager) { m.ResolveAll(config.ActionBlock, SourceKillSwitch) }},
		{"inventory", func(m *Manager) { m.ResolveToolInventory("session", config.ActionBlock) }},
		{"policy reload", func(m *Manager) {
			m.ResolvePolicyReload(func(HeldAction) (string, error) { return config.ActionBlock, nil })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				manager := NewManager(Config{Enabled: true, Timeout: time.Minute, MaxPending: 2})
				resolved := make(chan Resolution, 2)
				first, second := make(chan struct{}), make(chan struct{})
				hold := func(id string, release <-chan struct{}) error {
					return manager.HoldContext(t.Context(), HeldAction{
						DeferID:   id,
						Authority: AuthoritySnapshot{SessionID: "session"},
						RulePolicy: config.DeferResolutionPolicy{
							AllowOn: config.DeferAllowOn{ToolInventoryBaseline: true},
						},
						ConfirmHold: func(context.Context, HeldAction) error {
							<-release
							return nil
						},
						ConfirmResolution: func(context.Context, Resolution) error { return nil },
						Resolve:           func(result Resolution) { resolved <- result },
					})
				}
				results := make(chan error, 2)
				go func() { results <- hold("first", first) }()
				synctest.Wait()
				go func() { results <- hold("second", second) }()
				synctest.Wait()

				err := manager.Hold(HeldAction{DeferID: "third", Resolve: func(Resolution) {}})
				if !errors.Is(err, ErrCapacity) {
					t.Errorf("third hold = %v, want capacity error", err)
				}

				done := make(chan struct{})
				go func() {
					tc.resolve(manager)
					close(done)
				}()
				synctest.Wait()
				close(first)
				synctest.Wait()
				close(second)
				for range 2 {
					if err := <-results; err != nil {
						t.Fatal(err)
					}
				}
				<-done
				if got := manager.HeldCount(); got != 0 {
					t.Errorf("bulk resolution left %d holds", got)
				}
				if got := len(resolved); got != 2 {
					t.Fatalf("resolved %d holds, want 2", got)
				}
				for range 2 {
					if result := <-resolved; result.FinalDecision != config.ActionBlock {
						t.Errorf("unexpected resolution: %+v", result)
					}
				}
			})
		})
	}
}
