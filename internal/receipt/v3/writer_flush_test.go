// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type controlledFlushFile struct {
	StreamFile
	writes   chan struct{}
	syncs    chan chan error
	closed   chan struct{}
	stop     chan struct{}
	writeErr error
}

func controlWriterFlushes(t *testing.T, w *StreamWriter) *controlledFlushFile {
	t.Helper()
	w.gate <- struct{}{}
	f := &controlledFlushFile{
		StreamFile: w.active.file,
		writes:     make(chan struct{}, 32), syncs: make(chan chan error),
		closed: make(chan struct{}), stop: make(chan struct{}),
	}
	w.active.file = f
	w.release()
	t.Cleanup(func() { close(f.stop) })
	return f
}

func (f *controlledFlushFile) Write(data []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	n, err := f.StreamFile.Write(data)
	f.writes <- struct{}{}
	return n, err
}

func (f *controlledFlushFile) Sync() error {
	result := make(chan error, 1)
	select {
	case f.syncs <- result:
		select {
		case err := <-result:
			if err != nil {
				return err
			}
		case <-f.stop:
		}
	case <-f.stop:
	}
	return f.StreamFile.Sync()
}

func (f *controlledFlushFile) Close() error {
	close(f.closed)
	return f.StreamFile.Close()
}

func awaitFlushEvent[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("timed out waiting for receipt storage event")
		var zero T
		return zero
	}
}

func requirePending[T any](t *testing.T, ch <-chan T) {
	t.Helper()
	select {
	case value := <-ch:
		t.Fatalf("receipt operation completed early: %v", value)
	default:
	}
}

func asyncWriterResult(run func() error) <-chan error {
	result := make(chan error, 1)
	go func() { result <- run() }()
	return result
}

func appendTestIntent(t *testing.T, w *StreamWriter, f *controlledFlushFile, ctx context.Context, id string) <-chan error {
	t.Helper()
	result := asyncWriterResult(func() error { return w.WriteAction(ctx, writerTestIntent(id), PolicySnapshot{}) })
	awaitFlushEvent(t, f.writes)
	return result
}

func TestSharedFlushConfirmsCapturedPrefix(t *testing.T) {
	w := requireWriter(t, writerTestOptions(t.TempDir()), localWriterStorage())
	f := controlWriterFlushes(t, w)
	first := appendTestIntent(t, w, f, t.Context(), "first")
	syncFirst := awaitFlushEvent(t, f.syncs)
	second := appendTestIntent(t, w, f, t.Context(), "second")
	batch := asyncWriterResult(func() error {
		return w.WriteAdmissionBatch(t.Context(), []Action{writerTestIntent("batch-first"), writerTestIntent("batch-second")}, PolicySnapshot{})
	})
	awaitFlushEvent(t, f.writes)
	w.gate <- struct{}{}
	queued := len(w.pending)
	batchEnd := w.pending[queued-1].tip.Seq
	w.release()
	if queued != 3 || batchEnd != 4 {
		t.Fatalf("batch reservation: %d tickets through %d", queued, batchEnd)
	}
	requirePending(t, first)
	requirePending(t, second)
	requirePending(t, batch)
	syncFirst <- nil
	syncShared := awaitFlushEvent(t, f.syncs)
	if err := awaitFlushEvent(t, first); err != nil {
		t.Fatal(err)
	}
	requirePending(t, second)
	requirePending(t, batch)
	syncShared <- nil
	if err := errors.Join(awaitFlushEvent(t, second), awaitFlushEvent(t, batch)); err != nil {
		t.Fatal(err)
	}
}

func TestSharedFlushCancelsTwoTicketsBeforeReleasingNext(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	f := controlWriterFlushes(t, w)
	first := appendTestIntent(t, w, f, t.Context(), "preceding")
	syncFirst := awaitFlushEvent(t, f.syncs)
	ctx1, cancel1 := context.WithCancel(t.Context())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()
	request1 := appendTestIntent(t, w, f, ctx1, "cancel-one")
	request2 := appendTestIntent(t, w, f, ctx2, "cancel-two")
	last := appendTestIntent(t, w, f, t.Context(), "after-cancellation")
	syncFirst <- nil
	syncShared := awaitFlushEvent(t, f.syncs)
	cancel1()
	cancel2()
	syncShared <- nil
	if err := awaitFlushEvent(t, first); err != nil {
		t.Fatal(err)
	}
	repair1 := awaitFlushEvent(t, f.syncs)
	requirePending(t, request1)
	requirePending(t, request2)
	requirePending(t, last)
	repair1 <- nil
	repair2 := awaitFlushEvent(t, f.syncs)
	requirePending(t, request2)
	requirePending(t, last)
	repair2 <- nil
	for _, request := range []<-chan error{request1, request2} {
		if err := awaitFlushEvent(t, request); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrEffectNotReleased) {
			t.Fatalf("cancelled admission = %v, want confirmed refusal", err)
		}
	}
	if err := awaitFlushEvent(t, last); err != nil {
		t.Fatal(err)
	}
	verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if got := writerTestCount(t, verified, outcomeNotReleased); got != 2 {
		t.Fatalf("verified refusals = %d, want 2", got)
	}
}

func TestSharedFlushIgnoresRetiredSync(t *testing.T) {
	fault := errors.New("injected append fault")
	staleFault := errors.New("injected stale sync fault")
	for _, tc := range []struct {
		name    string
		syncErr error
	}{{"success", nil}, {"failure", staleFault}} {
		t.Run(tc.name, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			reported := make(chan error, 2)
			opts.OnDelayedSyncError = func(err error) { reported <- err }
			w := requireWriter(t, opts, localWriterStorage())
			f := controlWriterFlushes(t, w)
			openTip := w.active.confirmed
			stream := w.active.id
			first := appendTestIntent(t, w, f, t.Context(), "in-flight")
			stale := awaitFlushEvent(t, f.syncs)
			w.gate <- struct{}{}
			f.writeErr = fault
			w.release()
			second := asyncWriterResult(func() error {
				return w.WriteAction(t.Context(), writerTestIntent("torn"), PolicySnapshot{})
			})
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
			defer cancel()
			for {
				if err := w.acquire(ctx); err != nil {
					t.Fatal("append did not retire stream during Sync")
				}
				retired := w.active.file == nil
				w.release()
				if retired {
					break
				}
			}
			requirePending(t, f.closed)
			requirePending(t, first)
			stale <- tc.syncErr
			for _, request := range []<-chan error{first, second} {
				err := awaitFlushEvent(t, request)
				if !errors.Is(err, fault) || errors.Is(err, staleFault) || !errors.Is(err, ErrEffectNotReleased) {
					t.Fatalf("failed admission = %v, want append error and settled refusal", err)
				}
			}
			awaitFlushEvent(t, f.closed)
			requirePending(t, reported)
			if w.durability.FsyncErrorsGated != 1 {
				t.Fatalf("durability failures = %d, want 1", w.durability.FsyncErrorsGated)
			}
			verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
			for _, prior := range verified.Histories[0].Streams {
				if prior.Stream == stream && prior.Tip != nil && *prior.Tip == openTip {
					return
				}
			}
			t.Fatal("successor did not pin the original confirmed tip")
		})
	}
}

func TestSharedFlushErrorFanoutAndLaterFailure(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	policy := PolicySnapshot{}
	if err := w.WriteAction(t.Context(), writerTestIntent("confirmed"), policy); err != nil {
		t.Fatal(err)
	}
	f := controlWriterFlushes(t, w)
	first := appendTestIntent(t, w, f, t.Context(), "failed-prefix")
	result := awaitFlushEvent(t, f.syncs)
	tail := appendTestIntent(t, w, f, t.Context(), "failed-tail")
	fault := errors.New("injected shared sync fault")
	result <- fault
	for _, request := range []<-chan error{first, tail} {
		err := awaitFlushEvent(t, request)
		if !errors.Is(err, fault) || !errors.Is(err, ErrActionVisible) || !errors.Is(err, ErrEffectNotReleased) {
			t.Fatalf("failed group disposition: %v", err)
		}
	}
	w.gate <- struct{}{}
	w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: fault}
	w.release()
	if err := w.WriteAction(t.Context(), writerTestIntent("later-failure"), policy); !errors.Is(err, ErrEffectNotReleased) {
		t.Fatalf("later failed flush disposition: %v", err)
	}
	verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if writerTestCount(t, verified, outcomeNotReleased) != 3 || writerTestCount(t, verified, "outcome_unknown") != 1 {
		t.Fatalf("failed group damaged a prior confirmation or lost repair: %+v", verified.Counts)
	}
}

func TestSharedFlushDrainsBeforePublishingSegment(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	longDelay := time.Hour
	opts.idleFlushDelay = &longDelay
	w := requireWriter(t, opts, localWriterStorage())
	gate := NewEffectGate(w)
	token, err := gate.Admit(t.Context(), writerTestIntent("observed"), PolicySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	f := controlWriterFlushes(t, w)
	first := appendTestIntent(t, w, f, t.Context(), "before-outcome")
	syncFirst := awaitFlushEvent(t, f.syncs)
	if err := token.ConfirmDelivery(t.Context(), func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	awaitFlushEvent(t, f.writes)
	linked := make(chan struct{}, 1)
	w.gate <- struct{}{}
	w.fileBytes = w.active.bytes + maxLineBytes
	linkFile := w.storage.link
	w.storage.link = func(oldName, newName string) error {
		linked <- struct{}{}
		return linkFile(oldName, newName)
	}
	w.release()
	next := asyncWriterResult(func() error { return w.WriteAction(t.Context(), writerTestIntent("next-segment"), PolicySnapshot{}) })
	requirePending(t, linked)
	syncFirst <- nil
	if err := awaitFlushEvent(t, first); err != nil {
		t.Fatal(err)
	}
	syncOutcome := awaitFlushEvent(t, f.syncs)
	requirePending(t, linked)
	requirePending(t, next)
	syncOutcome <- nil
	awaitFlushEvent(t, linked)
	if err := awaitFlushEvent(t, next); err != nil {
		t.Fatal(err)
	}
	verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if got := writerTestCount(t, verified, "completed"); got != 1 {
		t.Fatalf("verified outcomes = %d, want 1", got)
	}
}

func TestCloseUnsealedBoundsWaitAndRetainsLock(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	f := controlWriterFlushes(t, w)
	request := appendTestIntent(t, w, f, t.Context(), "in-flight")
	flush := awaitFlushEvent(t, f.syncs)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := w.CloseUnsealed(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("bounded close = %v, want cancelled", err)
	}
	bounded := asyncWriterResult(func() error { return w.CloseUnsealed(context.Background()) })
	select {
	case err := <-bounded:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("writer-owned drain limit = %v, want deadline", err)
		}
	case <-time.After(testwait.Deadline(8 * time.Second)):
		t.Fatal("writer-owned drain limit did not bound close")
	}
	requirePending(t, f.closed)
	if second, err := OpenStreamWriter(t.Context(), opts); err == nil {
		_ = second.Close(t.Context(), nil)
		t.Fatal("directory lock was released with Sync in flight")
	}
	flush <- nil
	if err := errors.Join(awaitFlushEvent(t, request), w.CloseUnsealed(t.Context())); err != nil {
		t.Fatal(err)
	}
	awaitFlushEvent(t, f.closed)
	verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if got := verified.Histories[0].Streams[0].End; got != "open" {
		t.Fatalf("closed without seal: got %s", got)
	}
}

func TestObservedOutcomeFlushWithHeartbeatDisabled(t *testing.T) {
	fault := errors.New("injected delayed sync fault")
	for _, failedSuccessor := range []bool{false, true} {
		t.Run(map[bool]string{false: "recoverable", true: "fatal"}[failedSuccessor], func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			fast := time.Nanosecond
			opts.idleFlushDelay = &fast
			delayed := make(chan error, 2)
			fatal := make(chan error, 2)
			opts.OnDelayedSyncError = func(err error) { delayed <- err }
			opts.OnFatalError = func(err error) { fatal <- err }
			w := requireWriter(t, opts, localWriterStorage())
			gate := NewEffectGate(w)
			token, err := gate.Admit(t.Context(), writerTestIntent("observed"), PolicySnapshot{})
			if err != nil {
				t.Fatal(err)
			}
			f := controlWriterFlushes(t, w)
			if failedSuccessor {
				w.gate <- struct{}{}
				w.storage.createTemp = func(string, string) (StreamFile, error) { return nil, fault }
				w.release()
			}
			observed := asyncWriterResult(func() error {
				return token.ConfirmDelivery(t.Context(), func() (bool, error) { return true, nil })
			})
			if err := awaitFlushEvent(t, observed); err != nil {
				t.Fatal(err)
			}
			syncOutcome := awaitFlushEvent(t, f.syncs)
			syncOutcome <- fault
			if err := awaitFlushEvent(t, delayed); !errors.Is(err, fault) {
				t.Fatalf("delayed error = %v", err)
			}
			err = w.WriteHeartbeat(t.Context())
			if failedSuccessor {
				if fatalErr := awaitFlushEvent(t, fatal); !errors.Is(fatalErr, fault) || !errors.Is(err, ErrWriterUnavailable) {
					t.Fatalf("fatal callback = %v, subsequent write = %v", fatalErr, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				requirePending(t, fatal)
				verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
				if got := writerTestCount(t, verified, "completed"); got != 1 {
					t.Fatalf("verified repaired outcomes = %d, want 1", got)
				}
			}
			requirePending(t, delayed)
		})
	}
}

func TestOptionalGroupFailureWithholdsAdmissionsAndAllowsLocalDenials(t *testing.T) {
	for _, operation := range []string{"single", "batch", "local-denial"} {
		t.Run(operation, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			opts.Coverage.ReceiptsRequired = false
			w := requireWriter(t, opts, localWriterStorage())
			fault := errors.New("injected unavailable storage")
			w.gate <- struct{}{}
			w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: fault}
			w.storage.createTemp = func(string, string) (StreamFile, error) { return nil, fault }
			w.release()
			gate := NewEffectGate(w)
			action := writerTestIntent("intent")
			switch operation {
			case "single":
				_, err := gate.Admit(t.Context(), action, PolicySnapshot{})
				if !errors.Is(err, ErrActionPersistStarted) || errors.Is(err, ErrEffectNotReleased) {
					t.Fatalf("admission after failed recovery = %v", err)
				}
			case "batch":
				_, err := gate.AdmitBatch(t.Context(), []Action{action, writerTestIntent("support")}, PolicySnapshot{})
				if !errors.Is(err, ErrActionPersistStarted) || errors.Is(err, ErrEffectNotReleased) {
					t.Fatalf("batch admission after failed recovery = %v", err)
				}
			case "local-denial":
				if _, err := gate.AdmitDenialDelivery(t.Context(), action, PolicySnapshot{}); err != nil || len(w.repairs) != 0 {
					t.Fatalf("local denial withheld or repaired: %v, %d repairs", err, len(w.repairs))
				}
			}
			next := writerTestIntent("after-fatal-recovery")
			if operation == "local-denial" {
				if _, err := gate.AdmitDenialDelivery(t.Context(), next, PolicySnapshot{}); err != nil {
					t.Fatalf("optional local denial withheld after fatal recovery: %v", err)
				}
			} else {
				if token, err := gate.Admit(t.Context(), next, PolicySnapshot{}); token != nil || !errors.Is(err, ErrWriterUnavailable) {
					t.Fatalf("optional admission after fatal recovery: token=%v, error=%v", token, err)
				}
			}
		})
	}
}

func TestSharedFlushRefusalAndCloseStaySynchronous(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	longDelay := time.Hour
	opts.idleFlushDelay = &longDelay
	w := requireWriter(t, opts, localWriterStorage())
	gate := NewEffectGate(w)
	observed, err := gate.Admit(t.Context(), writerTestIntent("observed"), PolicySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	refused, err := gate.Admit(t.Context(), writerTestIntent("refused"), PolicySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	f := controlWriterFlushes(t, w)
	refusal := asyncWriterResult(func() error { return refused.Refuse(t.Context()) })
	retain := awaitFlushEvent(t, f.syncs)
	requirePending(t, refusal)
	retain <- nil
	if err := awaitFlushEvent(t, refusal); err != nil {
		t.Fatal(err)
	}
	if err := observed.ConfirmDelivery(t.Context(), func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	w.gate <- struct{}{}
	before := w.active.confirmed.Seq
	w.release()
	closing := asyncWriterResult(func() error { return w.Close(t.Context(), nil) })
	seal := awaitFlushEvent(t, f.syncs)
	w.gate <- struct{}{}
	gap := w.active.appended.Seq - before
	w.release()
	if gap != 2 {
		t.Fatalf("seal did not share an outcome flush: %d appended records", gap)
	}
	requirePending(t, closing)
	seal <- nil
	if err := awaitFlushEvent(t, closing); err != nil {
		t.Fatal(err)
	}
}

func TestSharedFlushCloseReplaysObservedOutcomeBeforeUnlock(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	longDelay := time.Hour
	opts.idleFlushDelay = &longDelay
	w := requireWriter(t, opts, localWriterStorage())
	intent := writerTestIntent("observed-before-close")
	intent.ParentActionID = "parent"
	token, err := NewEffectGate(w).Admit(t.Context(), intent, PolicySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("injected seal sync failure")
	w.gate <- struct{}{}
	w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: fault}
	w.release()
	if err := token.ConfirmDelivery(t.Context(), func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(t.Context(), nil); !errors.Is(err, fault) {
		t.Fatalf("close error = %v, want %v", err, fault)
	}
	actions := readRecoveryActions(t, opts.Dir, w.active.id)
	if len(actions) != 1 || actions[0].ParentActionID != intent.ParentActionID {
		t.Fatalf("replayed outcome lost parent attribution: %+v", actions)
	}
	verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if got := writerTestCount(t, verified, "completed"); got != 1 {
		t.Fatalf("verified repaired outcomes after close = %d, want 1", got)
	}
}

func TestSharedFlushReplaysOnlyOneCopyOfIdenticalObligation(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	f := controlWriterFlushes(t, w)
	first := appendTestIntent(t, w, f, t.Context(), "same")
	flush := awaitFlushEvent(t, f.syncs)
	second := appendTestIntent(t, w, f, t.Context(), "same")
	flush <- errors.New("injected duplicate append group failure")
	for _, request := range []<-chan error{first, second} {
		if err := awaitFlushEvent(t, request); !errors.Is(err, ErrEffectNotReleased) {
			t.Fatalf("shared obligation did not settle: %v", err)
		}
	}
	actions := readRecoveryActions(t, opts.Dir, w.active.id)
	if len(actions) != 1 || actions[0].OutcomeClass != outcomeNotReleased {
		t.Fatalf("copied obligations = %+v, want 1 refusal", actions)
	}
}

func TestIdleFlushUsesOldestObservedOutcome(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	longDelay := time.Hour
	opts.idleFlushDelay = &longDelay
	w := requireWriter(t, opts, localWriterStorage())
	gate := NewEffectGate(w)
	first, err := gate.Admit(t.Context(), writerTestIntent("oldest"), PolicySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	last, err := gate.Admit(t.Context(), writerTestIntent("newest"), PolicySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	f := controlWriterFlushes(t, w)
	observed := func() (bool, error) { return true, nil }
	if err := errors.Join(first.ConfirmDelivery(t.Context(), observed), last.ConfirmDelivery(t.Context(), observed)); err != nil {
		t.Fatal(err)
	}
	w.gate <- struct{}{}
	w.pending[0].observedAt = time.Now().Add(-2 * longDelay)
	w.wakeFlush()
	w.release()
	result := awaitFlushEvent(t, f.syncs)
	result <- nil
	if err := w.CloseUnsealed(t.Context()); err != nil {
		t.Fatal(err)
	}
	verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if got := writerTestCount(t, verified, "completed"); got != 2 {
		t.Fatalf("idle flush confirmed %d outcomes, want 2", got)
	}
}

func TestSharedFlushRetainsRepairsAcrossFailedSuccessor(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	fault := errors.New("injected sync fault")
	storage := localWriterStorage()
	create := storage.createTemp
	files := 0
	storage.createTemp = func(dir, pattern string) (StreamFile, error) {
		file, err := create(dir, pattern)
		files++
		if err != nil || files != 2 {
			return file, err
		}
		return &failRepairSyncFile{StreamFile: file, fault: fault}, nil
	}
	w := requireWriter(t, opts, storage)
	f := controlWriterFlushes(t, w)
	first := appendTestIntent(t, w, f, t.Context(), "first-repair")
	flush := awaitFlushEvent(t, f.syncs)
	last := appendTestIntent(t, w, f, t.Context(), "last-repair")
	flush <- fault
	for _, request := range []<-chan error{first, last} {
		if err := awaitFlushEvent(t, request); !errors.Is(err, ErrEffectNotReleased) {
			t.Fatalf("unsettled request: %v", err)
		}
	}
	verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if count := len(verified.Histories[0].Streams); count != 3 {
		t.Fatalf("stream count after two faults: %d, want 3", count)
	}
	if got := writerTestCount(t, verified, outcomeNotReleased); got != 2 {
		t.Fatalf("verified refusals after two faults: %d, want 2", got)
	}
}

type failRepairSyncFile struct {
	StreamFile
	fault  error
	opened bool
}

func (f *failRepairSyncFile) Sync() error {
	if f.opened {
		return f.fault
	}
	f.opened = true
	return f.StreamFile.Sync()
}

func TestSharedFlushHeartbeatAndRollover(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	longDelay := time.Hour
	opts.idleFlushDelay = &longDelay
	w := requireWriter(t, opts, localWriterStorage())
	gate := NewEffectGate(w)
	observed, err := gate.Admit(t.Context(), writerTestIntent("before-heartbeat"), PolicySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	inFlight, err := gate.Admit(t.Context(), writerTestIntent("across-rollover"), PolicySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	f := controlWriterFlushes(t, w)
	observedEffect := func() (bool, error) { return true, nil }
	if err := observed.ConfirmDelivery(t.Context(), observedEffect); err != nil {
		t.Fatal(err)
	}
	awaitFlushEvent(t, f.writes)
	firstBeat := asyncWriterResult(func() error { return w.WriteHeartbeat(t.Context()) })
	awaitFlushEvent(t, f.writes)
	firstSync := awaitFlushEvent(t, f.syncs)
	secondBeat := asyncWriterResult(func() error { return w.WriteHeartbeat(t.Context()) })
	awaitFlushEvent(t, f.writes)
	w.gate <- struct{}{}
	reserved := w.active.beat
	w.release()
	if reserved != 2 {
		t.Fatalf("reserved %d heartbeat beats before confirmation, want 2", reserved)
	}
	done := asyncWriterResult(func() error { return w.Rollover(t.Context()) })
	requirePending(t, firstBeat)
	requirePending(t, secondBeat)
	firstSync <- nil
	secondSync := awaitFlushEvent(t, f.syncs)
	if err := awaitFlushEvent(t, firstBeat); err != nil {
		t.Fatal(err)
	}
	w.gate <- struct{}{}
	confirmed := w.active.confirmed.Seq
	w.release()
	if confirmed != 4 {
		t.Fatalf("first heartbeat confirmed through %d, want intent, intent, outcome, heartbeat", confirmed)
	}
	requirePending(t, secondBeat)
	requirePending(t, done)
	secondSync <- nil
	seal := awaitFlushEvent(t, f.syncs)
	if err := awaitFlushEvent(t, secondBeat); err != nil {
		t.Fatal(err)
	}
	requirePending(t, done)
	seal <- nil
	if err := awaitFlushEvent(t, done); err != nil {
		t.Fatal(err)
	}
	if err := inFlight.ConfirmDelivery(t.Context(), observedEffect); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if got := writerTestCount(t, verified, "completed"); got != 2 {
		t.Fatalf("verified observations = %d, want 2", got)
	}
	streams := verified.Histories[0].Streams
	if len(streams) != 2 || streams[0].End != endedClosed || streams[1].End != endedClosed {
		t.Fatalf("rollover did not link two sealed streams: %+v", streams)
	}
}

func TestSharedFlushReservesSequenceForCancellationBeforeRollover(t *testing.T) {
	w := requireWriter(t, writerTestOptions(t.TempDir()), localWriterStorage())
	f := controlWriterFlushes(t, w)
	w.gate <- struct{}{}
	w.active.appended.Seq, w.active.confirmed.Seq = maxInteger-4, maxInteger-4
	oldStream := w.active.id
	w.release()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request := appendTestIntent(t, w, f, ctx, "last-intent")
	intentSync := awaitFlushEvent(t, f.syncs)
	heartbeat := asyncWriterResult(func() error { return w.WriteHeartbeat(t.Context()) })
	deadline, stop := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
	defer stop()
	for {
		if err := w.acquire(deadline); err != nil {
			t.Fatal("heartbeat did not wait for rollover")
		}
		rolling, tip := w.transition, w.active.appended.Seq
		w.release()
		if rolling {
			break
		}
		if tip != maxInteger-3 {
			t.Fatal("heartbeat used the last intent's settlement position")
		}
	}
	cancel()
	intentSync <- nil
	awaitFlushEvent(t, f.writes)
	repairSync := awaitFlushEvent(t, f.syncs)
	requirePending(t, heartbeat)
	repairSync <- nil
	if err := awaitFlushEvent(t, request); !errors.Is(err, ErrEffectNotReleased) {
		t.Fatalf("last admission could not settle: %v", err)
	}
	awaitFlushEvent(t, f.writes)
	sealSync := awaitFlushEvent(t, f.syncs)
	w.gate <- struct{}{}
	stream, seq := w.active.id, w.active.appended.Seq
	w.release()
	if stream != oldStream || seq != maxInteger-1 {
		t.Fatalf("last valid sequence was not reserved for the seal: got %s/%d", stream, seq)
	}
	sealSync <- nil
	if err := awaitFlushEvent(t, heartbeat); err != nil {
		t.Fatal(err)
	}
	if w.active.id == oldStream || w.active.confirmed.Seq != 1 {
		t.Fatalf("heartbeat did not move to a successor: %+v", w.active)
	}
}

func TestSharedFlushSerializesResolutionBehindPendingAction(t *testing.T) {
	for _, acrossSegment := range []bool{false, true} {
		name := "same-segment"
		if acrossSegment {
			name = "across-segment"
		}
		t.Run(name, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			w := requireWriter(t, opts, localWriterStorage())
			hold := writerTestHold("held-race")
			if err := w.WriteAction(t.Context(), hold, PolicySnapshot{}); err != nil {
				t.Fatal(err)
			}
			f := controlWriterFlushes(t, w)
			blockRes := blockingHoldResolution(hold, "operator", relationAfter, false)
			first := asyncWriterResult(func() error { return w.WriteAction(t.Context(), blockRes, PolicySnapshot{}) })
			awaitFlushEvent(t, f.writes)
			firstSync := awaitFlushEvent(t, f.syncs)
			if acrossSegment {
				w.gate <- struct{}{}
				w.fileBytes = w.active.bytes + maxLineBytes
				w.release()
			}
			allowRes := Action{
				ActionID: hold.ActionID, ActionType: hold.ActionType, Actor: hold.Actor, Principal: hold.Principal,
				Caller: hold.Caller, Data: hold.Data, Transport: hold.Transport, Method: hold.Method, Target: hold.Target,
				Phase: phaseResolution, Verdict: verdictAllow, EffectBoundary: approvalBoundary, EffectRelation: relationAfter,
				Hold: &Hold{ID: hold.Hold.ID, ResolutionPolicy: hold.Hold.Policy, ResolutionSource: "operator"},
			}
			second := asyncWriterResult(func() error { return w.WriteAction(t.Context(), allowRes, PolicySnapshot{}) })
			requirePending(t, second)
			firstSync <- nil
			if err := awaitFlushEvent(t, first); err != nil {
				t.Fatalf("first block resolution failed: %v", err)
			}
			if err := awaitFlushEvent(t, second); err == nil {
				t.Fatal("second resolution succeeded after closing block resolution")
			}
			closing := asyncWriterResult(func() error { return w.Close(t.Context(), nil) })
			awaitFlushEvent(t, f.syncs) <- nil
			if err := awaitFlushEvent(t, closing); err != nil {
				t.Fatal(err)
			}
			verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
			if got := writerTestCount(t, verified, "blocked"); got != 1 {
				t.Fatalf("verified blocked decisions = %d, want 1", got)
			}
		})
	}
}

func TestSharedFlushRefuseOutcomeReplayPreservesParent(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	w := requireWriter(t, opts, localWriterStorage())
	intent := writerTestIntent("refused-child")
	intent.ParentActionID = "parent"
	token, err := NewEffectGate(w).Admit(t.Context(), intent, PolicySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("injected refusal sync failure")
	w.gate <- struct{}{}
	w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: fault}
	w.release()
	if err := token.Refuse(t.Context()); !errors.Is(err, fault) || !errors.Is(err, ErrEffectNotReleased) {
		t.Fatalf("refuse error = %v, want %v and %v", err, fault, ErrEffectNotReleased)
	}
	actions := readRecoveryActions(t, opts.Dir, w.active.id)
	if len(actions) != 1 || actions[0].OutcomeClass != outcomeNotReleased || actions[0].ParentActionID != intent.ParentActionID {
		t.Fatalf("replayed refusal outcome lost parent attribution: %+v", actions)
	}
	if err := w.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	verified := verifyWritten(t, opts.Dir, opts.SigningKey.Public().(ed25519.PublicKey))
	if got := writerTestCount(t, verified, "not_released"); got != 1 {
		t.Fatalf("verified not_released outcomes = %d, want 1", got)
	}
}

func TestOptionalAdmissionClassifiesRolloverPublicationFailure(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Coverage.ReceiptsRequired = false
	w := requireWriter(t, opts, localWriterStorage())
	gate := NewEffectGate(w)
	fault := errors.New("injected rollover publication failure")
	w.gate <- struct{}{}
	link := w.storage.link
	w.storage.link = func(string, string) error { return fault }
	w.release()
	if err := w.Rollover(t.Context()); !errors.Is(err, fault) || errors.Is(err, errWriterNeedsRestart) {
		t.Fatalf("rollover before link: %v", err)
	}
	if token, err := gate.Admit(t.Context(), writerTestIntent("before-link"), PolicySnapshot{}); token != nil || err != nil {
		t.Fatalf("optional admission before link: token=%v err=%v", token, err)
	}

	w.gate <- struct{}{}
	w.storage.link = link
	w.storage.syncDir = func(string) error { return fault }
	w.release()
	if token, err := gate.Admit(t.Context(), writerTestIntent("after-link"), PolicySnapshot{}); token != nil ||
		!errors.Is(err, ErrWriterUnavailable) || !errors.Is(err, errWriterNeedsRestart) || !errors.Is(err, fault) {
		t.Fatalf("first optional admission after link: token=%v err=%v", token, err)
	}
}

func TestOptionalAdmissionWithholdsAfterFatalRecoveryAndClose(t *testing.T) {
	opts := writerTestOptions(t.TempDir())
	opts.Coverage.ReceiptsRequired = false
	w := requireWriter(t, opts, localWriterStorage())
	fault := errors.New("injected unavailable storage")
	w.gate <- struct{}{}
	w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: fault}
	w.storage.createTemp = func(string, string) (StreamFile, error) { return nil, fault }
	w.release()
	gate := NewEffectGate(w)
	if _, err := gate.Admit(t.Context(), writerTestIntent("failed-before-close"), PolicySnapshot{}); !errors.Is(err, ErrActionPersistStarted) {
		t.Fatalf("first admission = %v, want %v", err, ErrActionPersistStarted)
	}
	_ = w.Close(t.Context(), nil)
	if token, err := gate.Admit(t.Context(), writerTestIntent("after-fatal-close"), PolicySnapshot{}); token != nil || !errors.Is(err, ErrWriterUnavailable) {
		t.Fatalf("optional admission after fatal close: token=%v, err=%v", token, err)
	}
	if _, err := gate.AdmitDenialDelivery(t.Context(), writerTestIntent("local-denial-after-fatal-close"), PolicySnapshot{}); err != nil {
		t.Fatalf("optional local denial withheld after fatal close: %v", err)
	}
}

type oneShotSyncFaultFile struct {
	StreamFile
	faulted *atomic.Bool
	syncs   atomic.Int64
	at      int64
}

func (f *oneShotSyncFaultFile) Sync() error {
	if f.syncs.Add(1) == f.at && f.faulted.CompareAndSwap(false, true) {
		return errors.New("injected one-shot sync fault")
	}
	return f.StreamFile.Sync()
}

func TestSharedFlushConcurrentTrafficAndClose(t *testing.T) {
	for _, withFault := range []bool{false, true} {
		name := "healthy"
		if withFault {
			name = "transient-fault"
		}
		t.Run(name, func(t *testing.T) {
			opts := writerTestOptions(t.TempDir())
			delay := time.Millisecond
			opts.idleFlushDelay = &delay
			opts.Heartbeat = time.Second
			storage := localWriterStorage()
			var faulted atomic.Bool
			if withFault {
				create := storage.createTemp
				storage.createTemp = func(dir, pattern string) (StreamFile, error) {
					file, err := create(dir, pattern)
					if err != nil {
						return nil, err
					}
					return &oneShotSyncFaultFile{StreamFile: file, faulted: &faulted, at: 3}, nil
				}
			}
			w := requireWriter(t, opts, storage)
			w.gate <- struct{}{}
			w.fileBytes = maxLineBytes + 2048
			w.release()

			gate := NewEffectGate(w)
			policy := CapturePolicy(opts.PolicyHash)
			started := make(chan struct{}, 16)
			var wg sync.WaitGroup
			for worker := range 8 {
				wg.Go(func() {
					for i := range 20 {
						id := fmt.Sprintf("w%d-i%d", worker, i)
						reqCtx, cancel := context.WithCancel(t.Context())
						if i%5 == 0 {
							cancel()
						}
						if i%4 == 0 {
							tok, err := gate.AdmitBatch(reqCtx, []Action{writerTestIntent(id + "-a"), writerTestIntent(id + "-b")}, policy)
							if err == nil && tok != nil {
								select {
								case started <- struct{}{}:
								default:
								}
								_ = tok.ConfirmDelivery(t.Context(), func() (bool, error) { return true, nil })
							}
						} else {
							tok, err := gate.Admit(reqCtx, writerTestIntent(id), policy)
							if err == nil && tok != nil {
								select {
								case started <- struct{}{}:
								default:
								}
								if i%3 == 0 {
									_ = tok.Refuse(t.Context())
								} else {
									_ = tok.ConfirmDelivery(t.Context(), func() (bool, error) { return true, nil })
								}
							}
						}
						cancel()
					}
				})
			}
			wg.Go(func() {
				for range 4 {
					_ = w.WriteHeartbeat(t.Context())
					_ = w.Rollover(t.Context())
				}
			})
			awaitFlushEvent(t, started)
			closeErr := w.Close(context.Background(), nil)
			wg.Wait()
			if !withFault && closeErr != nil {
				t.Fatalf("healthy concurrent close returned %v", closeErr)
			}
			verified, err := VerifyPaths(t.Context(), []string{opts.Dir}, Options{
				Directory: true,
				Keys:      []ed25519.PublicKey{opts.SigningKey.Public().(ed25519.PublicKey)},
			})
			if err != nil {
				t.Fatal(err)
			}
			if verified.Integrity != "ok" {
				t.Fatalf("integrity = %s verdict = %s findings = %+v", verified.Integrity, verified.Verdict, verified.Findings)
			}
		})
	}
}

func TestSharedFlushNoGoroutineLeakAfterCloseAndFatal(t *testing.T) {
	waitStable := func(t *testing.T, base int) {
		t.Helper()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.After(testwait.Deadline(2 * time.Second))
		for {
			runtime.GC()
			if runtime.NumGoroutine() <= base+1 {
				return
			}
			select {
			case <-ticker.C:
			case <-deadline:
				t.Fatalf("goroutine leak: before=%d after=%d", base, runtime.NumGoroutine())
			}
		}
	}

	t.Run("normal-close", func(t *testing.T) {
		runtime.GC()
		base := runtime.NumGoroutine()
		for range 5 {
			opts := writerTestOptions(t.TempDir())
			opts.Heartbeat = time.Second
			w := requireWriter(t, opts, localWriterStorage())
			tok, err := NewEffectGate(w).Admit(t.Context(), writerTestIntent("clean"), PolicySnapshot{})
			if err != nil {
				t.Fatal(err)
			}
			if err := tok.ConfirmDelivery(t.Context(), func() (bool, error) { return true, nil }); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
		}
		waitStable(t, base)
	})

	t.Run("fatal-then-close", func(t *testing.T) {
		runtime.GC()
		base := runtime.NumGoroutine()
		for range 5 {
			opts := writerTestOptions(t.TempDir())
			opts.Heartbeat = time.Second
			fatalSeen := make(chan struct{}, 1)
			opts.OnFatalError = func(error) {
				select {
				case fatalSeen <- struct{}{}:
				default:
				}
			}
			w := requireWriter(t, opts, localWriterStorage())
			fault := errors.New("fatal storage")
			w.gate <- struct{}{}
			w.active.file = errorWriterFile{StreamFile: w.active.file, syncErr: fault}
			w.storage.createTemp = func(string, string) (StreamFile, error) { return nil, fault }
			w.release()
			_ = w.WriteAction(t.Context(), writerTestIntent("fail"), PolicySnapshot{})
			awaitFlushEvent(t, fatalSeen)
			_ = w.Close(t.Context(), nil)
		}
		waitStable(t, base)
	})
}
