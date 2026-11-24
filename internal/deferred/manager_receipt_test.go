// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"context"
	"errors"
	"path/filepath"
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
