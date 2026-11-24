// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func receiptAdmissionFixture(id string) HeldAction {
	return HeldAction{
		DeferID: id, ActionID: id, Authority: AuthoritySnapshot{SessionID: "session"},
		Receipt: &ReceiptHold{
			ConfirmHold:       func(context.Context, HeldAction) error { return nil },
			ConfirmResolution: func(_ context.Context, res Resolution) (string, error) { return res.FinalDecision, nil },
			ConfirmCorrection: func(context.Context, Resolution) error { return nil },
		},
		ResolveReceipt: func(Resolution, Release) {},
	}
}

func TestReceiptHoldWithJournalDoesNotConfirm(t *testing.T) {
	m := NewManager(Config{Enabled: true, JournalPath: filepath.Join(t.TempDir(), "holds.jsonl")})
	held := receiptAdmissionFixture("hold")
	called := false
	held.Receipt.ConfirmHold = func(context.Context, HeldAction) error {
		called = true
		return nil
	}
	if err := m.Hold(held); err == nil || called {
		t.Fatalf("journal manager accepted receipt-backed hold: called=%t err=%v", called, err)
	}
}

func TestReceiptHoldCanceledAdmissionReleasesExactByteCapacity(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: testwait.Deadline(time.Minute), MaxPendingBytes: 8})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	root := receiptAdmissionFixture("root")
	entered, finish := make(chan struct{}), make(chan struct{})
	root.Receipt.ConfirmHold = func(ctx context.Context, _ HeldAction) error {
		close(entered)
		select {
		case <-finish:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	rootDone := make(chan error, 1)
	go func() { rootDone <- m.HoldContext(ctx, root) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waiting := receiptAdmissionFixture("waiting")
	waiting.SizeBytes = 8
	waitCtx, cancelWait := context.WithCancel(ctx)
	defer cancelWait()
	waitDone := make(chan error, 1)
	go func() { waitDone <- m.HoldContext(waitCtx, waiting) }()
	testwait.For(t, time.Second, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.holds[waiting.DeferID] != nil
	}, "waiting admission with reserved bytes")
	overflow := receiptAdmissionFixture("overflow")
	overflow.SizeBytes = 1
	if err := m.Hold(overflow); !errors.Is(err, ErrCapacity) {
		t.Fatalf("waiting hold lost its byte reservation: %v", err)
	}
	cancelWait()
	if err := <-waitDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting admission returned %v", err)
	}
	close(finish)
	if err := <-rootDone; err != nil {
		t.Fatal(err)
	}
	if err := m.Hold(waiting); err != nil {
		t.Fatalf("eight-byte retry must fit the exact byte limit: %v", err)
	}
	m.ResolveAll(config.ActionBlock, SourceCancel)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reservations != 0 || m.totalBytes != 0 || len(m.lineage) != 0 || len(m.sessionReservations) != 0 {
		t.Fatal("hold manager retained reservations or ancestry after settlement")
	}
}

func TestReceiptHoldFailedConfirmationFreesReservation(t *testing.T) {
	m := NewManager(Config{Enabled: true, MaxPending: 1, MaxPendingPerSession: 1, MaxPendingBytes: 8})
	held := receiptAdmissionFixture("hold")
	held.SizeBytes = 8
	confirmErr := errors.New("fixture confirmation failure")
	held.Receipt.ConfirmHold = func(context.Context, HeldAction) error { return confirmErr }
	if err := m.Hold(held); !errors.Is(err, confirmErr) || m.HeldCount() != 0 {
		t.Fatalf("failed hold publication returned %v with %d holds", err, m.HeldCount())
	}
	incomplete := held
	incomplete.Receipt = &ReceiptHold{}
	if err := m.Hold(incomplete); err == nil {
		t.Fatal("receipt-backed hold needs all of its callbacks")
	}
	held.Receipt.ConfirmHold = func(context.Context, HeldAction) error { return nil }
	if err := m.Hold(held); err != nil {
		t.Fatalf("failed hold kept its capacity or lineage: %v", err)
	}
	m.ResolveAll(config.ActionBlock, SourceCancel)
}

func TestReceiptHoldAdmissionBlockEnforcedInTakeHold(t *testing.T) {
	t.Run("resolve_all_during_admission_blocks_racing_allow_and_lineage", func(t *testing.T) {
		m := NewManager(Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
		ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
		defer cancel()

		entered, releaseConfirm := make(chan struct{}), make(chan struct{})
		resolved := make(chan Resolution, 1)
		held := receiptAdmissionFixture("admitting")
		held.RulePolicy = config.DeferResolutionPolicy{AllowOn: config.DeferAllowOn{Approval: true}}
		held.Receipt.ConfirmHold = func(ctx context.Context, _ HeldAction) error {
			close(entered)
			select {
			case <-releaseConfirm:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		held.ResolveReceipt = func(res Resolution, _ Release) {
			resolved <- res
		}

		admitDone := make(chan error, 1)
		go func() { admitDone <- m.HoldContext(ctx, held) }()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}

		m.ResolveAll(config.ActionBlock, SourceCancel)

		// Lineage must already reflect the admission block before publication so
		// neither a concurrent child nor a racing allow can observe it unblocked.
		m.mu.Lock()
		node := m.lineage[held.DeferID]
		lineageBlocked := node != nil && node.blocked
		m.mu.Unlock()
		if !lineageBlocked {
			close(releaseConfirm)
			admitErr := <-admitDone
			t.Fatalf("ResolveAll during admission did not mark lineage blocked (HoldContext: %v)", admitErr)
		}
		close(releaseConfirm)
		if err := <-admitDone; err != nil {
			t.Fatalf("HoldContext: %v", err)
		}
		select {
		case res := <-resolved:
			if res.FinalDecision != config.ActionBlock || res.ResolutionSource != SourceCancel {
				t.Fatalf("resolved = %+v, want block/%s", res, SourceCancel)
			}
		case <-ctx.Done():
			t.Fatal("admitted hold did not close after ResolveAll")
		}
	})

	t.Run("take_hold_rejects_allow_when_admission_blocked", func(t *testing.T) {
		m := NewManager(Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
		resolved := make(chan Resolution, 1)
		held := receiptAdmissionFixture("raced")
		held.RulePolicy = config.DeferResolutionPolicy{AllowOn: config.DeferAllowOn{Approval: true}}
		held.ResolveReceipt = func(res Resolution, release Release) {
			if res.FinalDecision == config.ActionAllow {
				release.Commit()
			}
			resolved <- res
		}
		if err := m.Hold(held); err != nil {
			t.Fatal(err)
		}
		// Simulate the exact window right after publishHoldLocked before the
		// asynchronous AfterFunc(0) timer goroutine invokes Resolve.
		m.mu.Lock()
		m.holds[held.DeferID].admissionBlock = SourceCancel
		m.mu.Unlock()

		decision, err := m.ResolveApprovalResultContext(t.Context(), held.DeferID, config.ActionAllow, SourceOperator)
		if err != nil {
			t.Fatalf("ResolveApprovalResultContext: %v", err)
		}
		res := <-resolved
		if decision != config.ActionBlock || res.FinalDecision != config.ActionBlock || res.ResolutionSource != SourceCancel {
			t.Fatalf("racing allow bypassed admissionBlock: decision=%q res=%+v", decision, res)
		}
	})

	t.Run("step_up_cannot_bypass_cascade_block", func(t *testing.T) {
		m := NewManager(Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
		resolved := make(chan Resolution, 2)
		makeHeld := func(id string) HeldAction {
			h := receiptAdmissionFixture(id)
			h.RulePolicy = config.DeferResolutionPolicy{
				AllowOn:  config.DeferAllowOn{Approval: true},
				StepUpOn: config.DeferStepUpOn{ApprovalRequestsHuman: true},
			}
			h.ResolveReceipt = func(res Resolution, _ Release) { resolved <- res }
			return h
		}
		if err := m.Hold(makeHeld("parent")); err != nil {
			t.Fatal(err)
		}
		if err := m.Hold(makeHeld("child")); err != nil {
			t.Fatal(err)
		}
		// Simulate parent having closed its lineage before finishReceiptHold
		// resolves child, while an operator sends a step_up resolution for child.
		m.mu.Lock()
		m.lineage["child"].blocked = true
		m.mu.Unlock()

		decision, err := m.ResolveApprovalResultContext(t.Context(), "child", config.ActionStepUp, SourceOperator)
		if err != nil {
			t.Fatalf("ResolveApprovalResultContext step_up: %v", err)
		}
		res := <-resolved
		if decision != config.ActionBlock || res.FinalDecision != config.ActionBlock || res.ResolutionSource != SourceCascade {
			t.Fatalf("step_up bypassed cascade block: decision=%q res=%+v", decision, res)
		}
		m.ResolveAll(config.ActionBlock, SourceCancel)
	})
}

func TestReceiptHoldCancelledParkedWaiterDoesNotStrandBlockedChild(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: testwait.Deadline(time.Minute), MaxPending: 2, MaxPendingPerSession: 2})
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
	defer cancel()

	resolved := make(chan Resolution, 2)
	makeHeld := func(id string) HeldAction {
		h := receiptAdmissionFixture(id)
		h.RulePolicy = config.DeferResolutionPolicy{AllowOn: config.DeferAllowOn{Approval: true}}
		h.ResolveReceipt = func(res Resolution, _ Release) { resolved <- res }
		return h
	}
	if err := m.Hold(makeHeld("parent")); err != nil {
		t.Fatal(err)
	}
	if err := m.Hold(makeHeld("child")); err != nil {
		t.Fatal(err)
	}

	// Simulate a parked approval waiter being preempted across parent's
	// finishReceiptHold (which skips children with parkedApprovals > 0), then
	// exiting with ctx.Err() once parkedApprovals drops back to 0.
	m.mu.Lock()
	m.holds["child"].parkedApprovals = 1
	m.mu.Unlock()

	if err := m.Resolve("parent", config.ActionBlock, SourceOperator); err != nil {
		t.Fatalf("resolve parent: %v", err)
	}
	parentRes := <-resolved
	if parentRes.DeferID != "parent" || parentRes.FinalDecision != config.ActionBlock {
		t.Fatalf("parent resolution = %+v", parentRes)
	}

	m.mu.Lock()
	m.holds["child"].parkedApprovals = 0
	m.mu.Unlock()

	cancelledCtx, cancelOp := context.WithCancel(ctx)
	cancelOp()
	if _, err := m.ResolveApprovalResultContext(cancelledCtx, "child", config.ActionAllow, SourceOperator); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled approval = %v, want context.Canceled", err)
	}

	select {
	case childRes := <-resolved:
		if childRes.DeferID != "child" || childRes.FinalDecision != config.ActionBlock || childRes.ResolutionSource != SourceCascade {
			t.Fatalf("child resolution = %+v, want block/%s", childRes, SourceCascade)
		}
	case <-time.After(testwait.Deadline(500 * time.Millisecond)):
		m.ResolveAll(config.ActionBlock, SourceCancel)
		t.Fatal("cascade-blocked child remained stranded in StateHeld after parked approval cancelled")
	}

	testwait.ForContext(t, ctx, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.reservations == 0 && len(m.holds) == 0 && len(m.lineage) == 0
	}, "released child capacity and lineage")
}

func TestReceiptHoldStepUpHonorsDeadline(t *testing.T) {
	for _, tc := range []struct {
		name, decision, source string
		expired                bool
	}{
		{name: "before", decision: config.ActionAsk, source: SourceOperator},
		{name: "after", decision: config.ActionBlock, source: SourceTimeout, expired: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(Config{Enabled: true, Timeout: time.Minute})
			held := receiptAdmissionFixture("step-up")
			held.RulePolicy.StepUpOn.ApprovalRequestsHuman = true
			var resolution Resolution
			held.ResolveReceipt = func(res Resolution, _ Release) { resolution = res }
			if err := m.Hold(held); err != nil {
				t.Fatal(err)
			}
			m.mu.Lock()
			current := m.holds[held.DeferID]
			current.timer.Stop()
			if tc.expired {
				current.Deadline = time.Now().Add(-time.Second)
			}
			m.mu.Unlock()
			applied, err := m.ResolveApprovalResult(held.DeferID, config.ActionStepUp, SourceOperator)
			if err != nil || applied != tc.decision || resolution.ResolutionSource != tc.source {
				t.Fatalf("step-up = %q/%q (%v), want %q/%q", applied, resolution.ResolutionSource, err, tc.decision, tc.source)
			}
		})
	}
}

func TestReceiptHoldReloadCannotResolveReusedID(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Minute})
	const id = "reused"
	original := receiptAdmissionFixture(id)
	if err := m.Hold(original); err != nil {
		t.Fatal(err)
	}
	replacement := receiptAdmissionFixture(id)
	defer m.ResolveAll(config.ActionBlock, SourceCancel)

	m.ResolvePolicyReload(func(h HeldAction) (string, error) {
		if h.DeferID != id {
			t.Fatalf("evaluated hold %q, want %q", h.DeferID, id)
		}
		if err := m.Resolve(id, config.ActionBlock, SourceOperator); err != nil {
			t.Fatal(err)
		}
		if err := m.Hold(replacement); err != nil {
			t.Fatal(err)
		}
		return config.ActionBlock, nil
	})
	if _, ok := m.Held(id); !ok {
		t.Fatal("stale policy evaluation resolved the replacement hold")
	}
}

func TestReceiptHoldRetainsSweepApproval(t *testing.T) {
	for _, source := range []string{SourceToolInventory, SourcePolicyReload} {
		t.Run(source, func(t *testing.T) {
			for _, tc := range []struct {
				name, decision, source string
				commit, expired        bool
			}{
				{name: "commit", decision: config.ActionAllow, source: source, commit: true},
				{name: "refuse", decision: config.ActionBlock, source: SourceCascade},
				{name: "expired", decision: config.ActionBlock, source: SourceTimeout, commit: true, expired: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					m := NewManager(Config{Enabled: true, Timeout: time.Minute})
					parent := receiptAdmissionFixture("parent")
					child := receiptAdmissionFixture("child")
					child.RulePolicy.AllowOn.ToolInventoryBaseline = true
					child.RulePolicy.AllowOn.PolicyPermits = true
					parentReady := make(chan struct{})
					finishParent := make(chan struct{})
					parent.ResolveReceipt = func(_ Resolution, release Release) {
						if tc.commit {
							release.Commit()
						} else {
							release.Refuse("pre_send_refusal", nil)
						}
						close(parentReady)
						if tc.commit {
							<-finishParent
						}
					}
					results := make(chan Resolution, 1)
					child.ResolveReceipt = func(res Resolution, release Release) {
						if res.FinalDecision == config.ActionAllow {
							release.Commit()
						}
						results <- res
					}
					for _, held := range []HeldAction{parent, child} {
						if err := m.Hold(held); err != nil {
							t.Fatal(err)
						}
					}
					defer m.ResolveAll(config.ActionBlock, SourceCancel)
					defer close(finishParent)
					swept := make(chan struct{})
					go func() {
						defer close(swept)
						if source == SourceToolInventory {
							m.ResolveToolInventory(child.Authority.SessionID, config.ActionAllow)
						} else {
							m.ResolvePolicyReload(func(h HeldAction) (string, error) {
								if h.DeferID == child.DeferID {
									return config.ActionAllow, nil
								}
								return config.ActionDefer, nil
							})
						}
					}()
					select {
					case <-swept:
					case <-time.After(testwait.Deadline(time.Second)):
						t.Fatal("sweep blocked on the parent")
					}
					if m.HeldCount() != 2 {
						t.Fatal("sweep released the child before the parent's commitment")
					}
					if tc.expired {
						m.mu.Lock()
						current := m.holds[child.DeferID]
						current.timer.Stop()
						current.Deadline = time.Now().Add(-time.Second)
						m.mu.Unlock()
					}
					parentDone := make(chan error, 1)
					go func() { parentDone <- m.Resolve(parent.DeferID, config.ActionAllow, SourceOperator) }()
					select {
					case <-parentReady:
					case <-time.After(testwait.Deadline(time.Second)):
						t.Fatal("parent did not reach the send boundary")
					}
					select {
					case res := <-results:
						if res.FinalDecision != tc.decision || res.ResolutionSource != tc.source {
							t.Fatalf("child = %q/%q, want %q/%q", res.FinalDecision, res.ResolutionSource, tc.decision, tc.source)
						}
					case <-time.After(testwait.Deadline(time.Second)):
						t.Fatal("child did not settle after parent decided; sweep result was delivered once")
					}
					if !tc.commit {
						if err := <-parentDone; err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func TestReceiptHoldWaitsForConfirmedParentBeforeLinking(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Minute, MaxCascadeDepth: 1})
	writing, resume := make(chan struct{}), make(chan struct{})
	unpause := sync.OnceFunc(func() { close(resume) })
	defer unpause()
	parent := receiptAdmissionFixture("parent")
	parent.Receipt.ConfirmHold = func(context.Context, HeldAction) error {
		close(writing)
		<-resume
		return nil
	}
	parentDone := make(chan error, 1)
	go func() { parentDone <- m.Hold(parent) }()
	receiveReceiptFixture(t, writing)
	defer m.ResolveAll(config.ActionBlock, SourceCancel)
	child := receiptAdmissionFixture("child")
	child.Receipt.ConfirmHold = func(context.Context, HeldAction) error {
		return errors.New("cascade-limited child must not confirm a hold")
	}
	childDone := make(chan error, 1)
	go func() { childDone <- m.Hold(child) }()
	testwait.For(t, time.Second, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.reservations == 2
	}, "child reserving capacity behind parent confirmation")
	if got := m.HeldCount(); got != 0 {
		t.Fatalf("held count during confirmation = %d, want 0", got)
	}
	unpause()
	if err := receiveReceiptFixture(t, parentDone); err != nil {
		t.Fatal(err)
	}
	var limit *CascadeLimitError
	err := receiveReceiptFixture(t, childDone)
	if !errors.As(err, &limit) || limit.ParentDeferID != parent.DeferID || limit.Depth != 2 {
		t.Fatalf("child admission = %v, depth error %+v", err, limit)
	}
	if count := m.HeldCount(); count != 1 {
		t.Fatalf("held count after rejection = %d, want 1", count)
	}
}

func receiveReceiptFixture[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(testwait.Deadline(time.Second)):
		t.Fatal("timed out waiting for manager")
		var zero T
		return zero
	}
}

func TestReceiptHoldParkedApprovalSettlement(t *testing.T) {
	for _, mode := range []string{"commit", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			m := NewManager(Config{Enabled: true, Timeout: time.Minute})
			defer m.ResolveAll(config.ActionBlock, SourceCancel)
			parent := receiptAdmissionFixture("parent")
			parent.ResolveReceipt = func(res Resolution, release Release) {
				if res.FinalDecision == config.ActionAllow {
					release.Commit()
				}
			}
			child := receiptAdmissionFixture("child")
			child.RulePolicy.AllowOn.Approval = true
			resolved := make(chan Resolution, 1)
			child.ResolveReceipt = func(res Resolution, release Release) {
				if res.FinalDecision == config.ActionAllow {
					release.Commit()
				}
				resolved <- res
			}
			for _, held := range []HeldAction{parent, child} {
				if err := m.Hold(held); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				_, err := m.ResolveApprovalResultContext(ctx, child.DeferID, config.ActionAllow, SourceOperator)
				finished <- err
			}()
			testwait.For(t, time.Second, func() bool {
				m.mu.Lock()
				defer m.mu.Unlock()
				return m.holds[child.DeferID].parkedApprovals == 1
			}, "child parked behind uncommitted parent")
			switch mode {
			case "cancel":
				cancel()
				if err := receiveReceiptFixture(t, finished); !errors.Is(err, context.Canceled) {
					t.Fatalf("parked approval returned %v", err)
				}
				if _, ok := m.Held(child.DeferID); !ok {
					t.Fatal("cancelled approval consumed child hold")
				}
				return
			case "deadline":
				// Expire the original deadline while the approval is parked.
				m.mu.Lock()
				m.holds[child.DeferID].Deadline = time.Now().Add(-time.Second)
				m.notifyHoldChangeLocked()
				m.mu.Unlock()
			case "commit":
				if err := m.Resolve(parent.DeferID, config.ActionAllow, SourceOperator); err != nil {
					t.Fatal(err)
				}
			}
			if err := receiveReceiptFixture(t, finished); err != nil {
				t.Fatal(err)
			}
			wantDecision, wantSource := config.ActionAllow, SourceOperator
			if mode == "deadline" {
				wantDecision, wantSource = config.ActionBlock, SourceTimeout
			}
			if got := receiveReceiptFixture(t, resolved); got.FinalDecision != wantDecision || got.ResolutionSource != wantSource {
				t.Fatalf("parked approval settled as %q/%q, want %q/%q", got.FinalDecision, got.ResolutionSource, wantDecision, wantSource)
			}
		})
	}
}

func TestReceiptHoldAllowWhenSettlementFails(t *testing.T) {
	failure := errors.New("receipt storage unavailable")
	for _, tc := range []struct {
		name, confirmation string
		confirm, settle    error
	}{
		{name: "repaired_block", confirmation: config.ActionBlock},
		{name: "unsettled_allow", confirm: failure},
		{name: "unsettled_refusal", confirmation: config.ActionAllow, settle: failure},
		{name: "callback_omits_commit", confirmation: config.ActionAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(Config{Enabled: true, Timeout: time.Minute})
			held := receiptAdmissionFixture("parent")
			held.RulePolicy.AllowOn.Approval = true
			held.Receipt.ConfirmResolution = func(context.Context, Resolution) (string, error) { return tc.confirmation, tc.confirm }
			var corrected Resolution
			held.Receipt.ConfirmCorrection = func(_ context.Context, res Resolution) error {
				corrected = res
				return nil
			}
			var result Resolution
			held.ResolveReceipt = func(res Resolution, release Release) {
				result = res
				if tc.settle != nil {
					result = release.Refuse("intent_refused", func() error { return tc.settle })
					if second := release.Refuse("second_refusal", nil); second.Reason != result.Reason {
						t.Errorf("second refusal changed reason to %q", second.Reason)
					}
				}
			}
			if err := m.Hold(held); err != nil {
				t.Fatal(err)
			}
			applied, err := m.ResolveApprovalResult(held.DeferID, config.ActionAllow, SourceOperator)
			wantErr := errors.Join(tc.confirm, tc.settle)
			if (wantErr != nil && !errors.Is(err, failure)) || (wantErr == nil && err != nil) {
				t.Fatalf("resolution error = %v, want %v", err, wantErr)
			}
			if wantErr == nil && applied != config.ActionBlock {
				t.Fatalf("resolved %q, want block", applied)
			}
			if tc.name == "callback_omits_commit" {
				result = corrected
			}
			if result.FinalDecision != config.ActionBlock || result.ResolutionSource != SourceCancel {
				t.Fatalf("unreleased hold callback = %+v", result)
			}
			if count := m.HeldCount(); count != 0 {
				t.Fatalf("resolved hold remains pending, count = %d", count)
			}
		})
	}
}

func TestHoldFailureSourceCancellation(t *testing.T) {
	for _, tc := range []struct {
		err    error
		source string
	}{
		{err: context.DeadlineExceeded, source: SourceTimeout},
		{err: context.Canceled, source: SourceCancel},
	} {
		if got := HoldFailureSource(fmt.Errorf("admit held request: %w", tc.err)); got != tc.source {
			t.Errorf("failure source for %v = %q, want %q", tc.err, got, tc.source)
		}
	}
}

func TestReceiptCascadeSweepKeepsReplacementHold(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: time.Minute})
	parent := receiptAdmissionFixture("parent")
	first := receiptAdmissionFixture("first")
	second := receiptAdmissionFixture("second")
	first.Authority.SessionID, second.Authority.SessionID = "left", "right"
	var replaced string
	replaceOther := func(id string) func(Resolution, Release) {
		return func(Resolution, Release) {
			if replaced != "" {
				return
			}
			replaced = id
			if err := m.Resolve(id, config.ActionBlock, SourceOperator); err != nil {
				t.Fatal(err)
			}
			replacement := receiptAdmissionFixture(id)
			replacement.Authority.SessionID = "replacement"
			if err := m.Hold(replacement); err != nil {
				t.Fatal(err)
			}
		}
	}
	first.ResolveReceipt, second.ResolveReceipt = replaceOther(second.DeferID), replaceOther(first.DeferID)
	for _, held := range []HeldAction{parent, first, second} {
		if err := m.Hold(held); err != nil {
			t.Fatal(err)
		}
	}
	defer m.ResolveAll(config.ActionBlock, SourceCancel)
	// Install two sibling descendants so the first callback can replace the
	// other hold regardless of map traversal order.
	m.mu.Lock()
	root := m.lineage[parent.DeferID]
	m.lineage[first.DeferID].parent, m.lineage[second.DeferID].parent = root, root
	root.children = 2
	m.mu.Unlock()
	if err := m.Resolve(parent.DeferID, config.ActionBlock, SourceOperator); err != nil {
		t.Fatal(err)
	}
	held, ok := m.Held(replaced)
	if !ok || held.Authority.SessionID != "replacement" {
		t.Fatalf("stale cascade consumed replacement hold %q", replaced)
	}
}

func TestReceiptHoldLatestSweepRevokesApproval(t *testing.T) {
	m := NewManager(Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
	parent := receiptAdmissionFixture("parent")
	parent.ResolveReceipt = func(_ Resolution, release Release) { release.Commit() }
	child := receiptAdmissionFixture("child")
	child.RulePolicy.AllowOn.PolicyPermits = true
	resolved := make(chan Resolution, 1)
	child.ResolveReceipt = func(res Resolution, release Release) {
		if res.FinalDecision == config.ActionAllow {
			release.Commit()
		}
		resolved <- res
	}
	for _, held := range []HeldAction{parent, child} {
		if err := m.Hold(held); err != nil {
			t.Fatal(err)
		}
	}
	defer m.ResolveAll(config.ActionBlock, SourceCancel)

	for _, decision := range []string{config.ActionAllow, config.ActionDefer} {
		m.ResolvePolicyReload(func(h HeldAction) (string, error) {
			if h.DeferID == child.DeferID {
				return decision, nil
			}
			return config.ActionDefer, nil
		})
	}
	m.mu.Lock()
	hasApproval := m.holds[child.DeferID].sweepApproval.source != ""
	m.mu.Unlock()
	if err := m.Resolve(parent.DeferID, config.ActionAllow, SourceOperator); err != nil {
		t.Fatal(err)
	}
	if hasApproval {
		res := receiveReceiptFixture(t, resolved)
		t.Fatalf("newer defer left the sweep approval active: child resolved as %q", res.FinalDecision)
	}
	if _, ok := m.Held(child.DeferID); !ok {
		t.Fatal("child did not remain held after the parent committed")
	}
}

func TestReceiptHoldSweepSequences(t *testing.T) {
	const (
		policyAllow    = "policy-allow"
		policyDefer    = "policy-defer"
		inventoryAllow = "inventory-allow"
		inventoryDefer = "inventory-defer"
		inventoryBlock = "inventory-block"
		parentCommit   = "parent-commit"
		parentBlock    = "parent-block"
	)
	events := []string{policyAllow, policyDefer, inventoryAllow, inventoryDefer, inventoryBlock, parentCommit, parentBlock}
	var enumerate func([]string, bool)
	enumerate = func(sequence []string, decided bool) {
		if len(sequence) == 3 {
			return
		}
		for _, event := range events {
			parentDecision := event == parentCommit || event == parentBlock
			if parentDecision && decided {
				continue
			}
			next := append(sequence, event)
			for _, policyPermitted := range []bool{false, true} {
				for _, inventoryPermitted := range []bool{false, true} {
					name := fmt.Sprintf("%s/policy=%t/inventory=%t", strings.Join(next, "_"), policyPermitted, inventoryPermitted)
					t.Run(name, func(t *testing.T) {
						m := NewManager(Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
						parent := receiptAdmissionFixture("parent")
						parent.ResolveReceipt = func(res Resolution, release Release) {
							if res.FinalDecision == config.ActionAllow {
								release.Commit()
							}
						}
						child := receiptAdmissionFixture("child")
						child.RulePolicy.AllowOn.PolicyPermits = policyPermitted
						child.RulePolicy.AllowOn.ToolInventoryBaseline = inventoryPermitted
						resolved := make(chan Resolution, 2)
						child.ResolveReceipt = func(res Resolution, release Release) {
							if res.FinalDecision == config.ActionAllow {
								release.Commit()
							}
							resolved <- res
						}
						for _, held := range []HeldAction{parent, child} {
							if err := m.Hold(held); err != nil {
								t.Fatal(err)
							}
						}
						defer m.ResolveAll(config.ActionBlock, SourceCancel)

						var committed, sent, blocked, latestPermitted bool
						for _, step := range next {
							switch step {
							case policyAllow, policyDefer:
								latestPermitted = step == policyAllow && policyPermitted
								m.ResolvePolicyReload(func(h HeldAction) (string, error) {
									if h.DeferID == child.DeferID && step == policyAllow {
										return config.ActionAllow, nil
									}
									return config.ActionDefer, nil
								})
							case inventoryAllow, inventoryDefer, inventoryBlock:
								decision := config.ActionDefer
								switch step {
								case inventoryAllow:
									decision = config.ActionAllow
								case inventoryBlock:
									decision = config.ActionBlock
								}
								latestPermitted = step == inventoryAllow && inventoryPermitted
								blocked = blocked || (!sent && step == inventoryBlock && inventoryPermitted)
								m.ResolveToolInventory(child.Authority.SessionID, decision)
							case parentCommit, parentBlock:
								committed = step == parentCommit
								blocked = blocked || !committed
								decision := config.ActionBlock
								if committed {
									decision = config.ActionAllow
								}
								if err := m.Resolve(parent.DeferID, decision, SourceOperator); err != nil {
									t.Fatal(err)
								}
							}
							if !sent && !blocked && committed && latestPermitted {
								if got := receiveReceiptFixture(t, resolved); got.FinalDecision != config.ActionAllow {
									t.Fatalf("after %s child resolved as %q, want allow", step, got.FinalDecision)
								}
								sent = true
							}
							m.mu.Lock()
							current := m.holds[child.DeferID]
							retained := current != nil && current.sweepApproval.source != ""
							m.mu.Unlock()
							wantHeld := !sent && !blocked
							if (current != nil) != wantHeld || retained != (wantHeld && !committed && latestPermitted) {
								t.Fatalf("after %s child held=%t retained=%t, model held=%t permitted=%t committed=%t",
									step, current != nil, retained, wantHeld, latestPermitted, committed)
							}
						}
						for len(resolved) != 0 {
							if got := <-resolved; got.FinalDecision != config.ActionBlock {
								t.Fatalf("unexpected child send: %+v", got)
							}
						}
					})
				}
			}
			enumerate(next, decided || parentDecision)
		}
	}
	enumerate(nil, false)
}
