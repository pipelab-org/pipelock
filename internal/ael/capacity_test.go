// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestCapacityConcurrentAdmissionsLeaveVerifiableClose(t *testing.T) {
	e, dir, signer := newIncrementalRun(t)
	activity := Activity{Class: "read", Direction: "in", ID: "example"}
	recordLimit := ActivityRecordLimit(len(activity.Class), len(activity.ID))
	const admitted = 8
	limit := e.written + maxCloseBytes + admitted*recordLimit
	e.capacity = NewCapacity(limit)
	capacity := e.capacity

	const attempts = 128
	results := make(chan *Lease, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			lease, err := e.Reserve(1, recordLimit)
			if errors.Is(err, ErrCapacity) {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			results <- lease
		})
	}
	wg.Wait()
	close(results)
	if got := len(results); got != admitted {
		t.Fatalf("admitted %d units, want %d", got, admitted)
	}
	select {
	case <-capacity.Stopped():
	default:
		t.Fatal("first refusal did not stop admission")
	}
	select {
	case <-capacity.Drained():
		t.Fatal("drain completed before the admitted units")
	default:
	}

	for lease := range results {
		record, err := e.PrepareActivity(activity, lease)
		if err != nil {
			t.Fatal(err)
		}
		if err := record.Append(false); err != nil {
			t.Fatal(err)
		}
		lease.Release()
		lease.Release()
	}
	select {
	case <-capacity.Drained():
	default:
		t.Fatal("drain did not account for settled units")
	}
	if err := e.EmitClose(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(e.Dir(), "recorders", "pipelock.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != e.written || info.Size() > limit {
		t.Fatalf("stream size = %d, accounted = %d, ceiling = %d", info.Size(), e.written, limit)
	}
	head, err := VerifyRun(dir, incrementalRunID, signer)
	if err != nil || head.RecordCount != admitted+2 {
		t.Fatalf("verifiable close: head=%+v err=%v", head, err)
	}
	t.Logf("admitted=%d refused=%d bytes=%d ceiling=%d verified_records=%d", admitted, attempts-admitted, info.Size(), limit, head.RecordCount)
}

func TestCapacityAccountsForPreparedRecordUntilCanceled(t *testing.T) {
	e, _, _ := newIncrementalRun(t)
	activity := Activity{Class: "read", Direction: "in", ID: "example"}
	bound := ActivityRecordLimit(len(activity.Class), len(activity.ID))
	e.capacity = NewCapacity(e.written + maxCloseBytes + bound)
	lease, err := e.Reserve(1, bound)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := e.PrepareActivity(activity, lease)
	if err != nil {
		t.Fatal(err)
	}
	if competing, err := e.Reserve(1, 1); !errors.Is(err, ErrCapacity) {
		competing.Release()
		t.Fatalf("reserve against pending slot: %v, want %v", err, ErrCapacity)
	}
	pending.Cancel()
	pending.Cancel()
	if available := e.availableBytes(); available != 0 {
		t.Fatalf("available after cancel=%d, want 0", available)
	}
	if err := pending.Append(false); err == nil {
		t.Fatal("canceled record was appended")
	}
	lease.Release()
	if available := e.availableBytes(); available != bound {
		t.Fatalf("available after release=%d, want %d", available, bound)
	}
	if err := e.EmitClose(); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityWriterRefusesOversizeBeforeAdvancing(t *testing.T) {
	e, dir, signer := newIncrementalRun(t)
	if err := e.EmitActivity(Activity{Class: "read", Direction: "in", ID: strings.Repeat("x", maxVerifyRecordBytes)}, false); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("oversized line: %v", err)
	}
	e.capacity = NewCapacity(e.written + maxCloseBytes)
	if err := e.EmitHeartbeat(); !errors.Is(err, ErrCapacity) {
		t.Fatalf("over-capacity heartbeat: %v", err)
	}
	if err := e.EmitClose(); err != nil {
		t.Fatal(err)
	}
	if head, err := VerifyRun(dir, incrementalRunID, signer); err != nil || head.RecordCount != 2 {
		t.Fatalf("close after refusal: head=%+v err=%v", head, err)
	}
}

func TestCapacityReleaseWaitsForPreparedRecord(t *testing.T) {
	for _, appendRecord := range []bool{true, false} {
		name := "cancel"
		if appendRecord {
			name = "append"
		}
		t.Run(name, func(t *testing.T) {
			e, _, _ := newIncrementalRun(t)
			activity := Activity{Class: "read", Direction: "in", ID: "example"}
			bound := ActivityRecordLimit(len(activity.Class), len(activity.ID))
			e.capacity = NewCapacity(e.written + maxCloseBytes + bound)
			lease, err := e.Reserve(1, bound)
			if err != nil {
				t.Fatal(err)
			}
			record, err := e.PrepareActivity(activity, lease)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.Reserve(1, bound); !errors.Is(err, ErrCapacity) {
				t.Fatalf("triggering stop: %v", err)
			}
			lease.Release()
			select {
			case <-e.capacity.Drained():
				t.Fatal("drain counted a pending record as settled")
			default:
			}
			if appendRecord {
				if err := record.Append(false); err != nil {
					t.Fatal(err)
				}
			} else {
				record.Cancel()
			}
			select {
			case <-e.capacity.Drained():
			default:
				t.Fatal("drain did not settle after resolving the pending record")
			}
			if err := e.EmitClose(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCapacityRefusesInvalidReservations(t *testing.T) {
	e, _, _ := newIncrementalRun(t)
	other, _, _ := newIncrementalRun(t)
	activity := Activity{Class: "read", Direction: "in", ID: "example"}
	bound := ActivityRecordLimit(len(activity.Class), len(activity.ID))
	for _, invalid := range []struct {
		records int
		bytes   int64
	}{{0, bound}, {1, 0}, {1, maxVerifyRecordBytes + 1}} {
		if _, err := e.Reserve(invalid.records, invalid.bytes); err == nil {
			t.Fatalf("reserved invalid capacity: %+v", invalid)
		}
	}
	lease, err := e.Reserve(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.PrepareActivity(activity, lease); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("oversized record in reservation: %v", err)
	}
	if _, err := other.PrepareActivity(activity, lease); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("used another stream's reservation: %v", err)
	}
	lease.Release()
	if _, err := e.PrepareActivity(activity, lease); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("used a released reservation: %v", err)
	}
	if err := e.EmitClose(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Reserve(1, bound); err == nil {
		t.Fatal("closed stream admitted work")
	}
	if err := other.EmitClose(); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityDrainIncludesUnreservedPreparedRecord(t *testing.T) {
	e, _, _ := newIncrementalRun(t)
	activity := Activity{Class: "read", Direction: "in", ID: "example"}
	bound := ActivityRecordLimit(len(activity.Class), len(activity.ID))
	e.capacity = NewCapacity(e.written + maxCloseBytes + bound)
	record, err := e.PrepareActivity(activity, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Reserve(1, bound); !errors.Is(err, ErrCapacity) {
		t.Fatalf("expected the prepared write to consume capacity: %v", err)
	}
	select {
	case <-e.capacity.Drained():
		t.Fatal("drain completed before the prepared write")
	default:
	}
	if err := record.Append(false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.capacity.Drained():
	default:
		t.Fatal("drain did not account for the appended record")
	}
	if err := e.EmitClose(); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityPreparedRecordPreconditions(t *testing.T) {
	var absent *Emitter
	var released *Lease
	if absent.Capacity().Stopped() != nil {
		t.Fatal("absent emitter has a stop signal")
	}
	if lease, err := absent.Reserve(1, 1); lease != nil || err != nil {
		t.Fatalf("absent emitter reserved capacity: %v %v", lease, err)
	}
	released.Release()
	pending, err := absent.PrepareOpen()
	if err != nil || pending != nil {
		t.Fatalf("absent emitter prepared record: %v %v", pending, err)
	}
	pending.Cancel()
	if err := pending.Append(false); err != nil {
		t.Fatal(err)
	}

	e, _, _ := newIncrementalRun(t)
	if _, err := e.PrepareActivity(Activity{}, nil); err == nil {
		t.Fatal("invalid record accepted")
	}
	pending, err = e.PrepareHeartbeat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.PrepareClose(); err == nil {
		t.Fatal("second record prepared before the first settled")
	}
	if err := e.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := pending.Append(false); err == nil {
		t.Fatal("aborted record accepted")
	}
}

func TestCapacitySplitsAlreadyReservedRecordsAfterStop(t *testing.T) {
	e, dir, signer := newIncrementalRun(t)
	const records = 2
	activity := Activity{Class: "read", Direction: "in", ID: "fixture"}
	bound := ActivityRecordLimit(len(activity.Class), len(activity.ID))
	e.capacity = NewCapacity(e.written + maxCloseBytes + records*bound)
	parent, err := e.Reserve(records, bound)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	finish := parent.OnStop(func() { close(closed) })
	if _, err := e.Reserve(1, bound); !errors.Is(err, ErrCapacity) {
		t.Fatalf("reserve past capacity: %v", err)
	}
	defer finish()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("stop callback did not run")
	}
	child, err := parent.Split(1)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []int{-1, 0, 2} {
		if _, err := parent.Split(invalid); !errors.Is(err, ErrInvalidLease) {
			t.Fatalf("split %d: %v", invalid, err)
		}
	}
	parent.Release()
	select {
	case <-e.capacity.Drained():
		t.Fatal("drained while split reservation was active")
	default:
	}
	if _, err := parent.Split(1); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("split released lease: %v", err)
	}
	record, err := e.PrepareActivity(activity, child)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Append(false); err != nil {
		t.Fatal(err)
	}
	child.Release()
	select {
	case <-e.capacity.Drained():
	default:
		t.Fatal("capacity did not drain after the final release")
	}
	if err := e.EmitClose(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRun(dir, e.run, signer); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityLeaseCanDisarmStreamStop(t *testing.T) {
	e, _, _ := newIncrementalRun(t)
	var missing *Lease
	if lease, err := missing.Split(1); lease != nil || err != nil {
		t.Fatalf("split nil lease: %v, %v", lease, err)
	}
	if lease, err := missing.Reserve(1); lease != nil || err != nil {
		t.Fatalf("reserve with nil lease: %v, %v", lease, err)
	}
	missing.OnStop(func() { t.Error("nil lease closed a stream") })()
	if missing.Stopping() {
		t.Fatal("nil lease reports a stop")
	}
	bound := ActivityRecordLimit(4, 8)
	parent, err := e.Reserve(1, bound)
	if err != nil {
		t.Fatal(err)
	}
	if parent.Stopping() {
		t.Fatal("admission stopped before the limit")
	}
	finish := parent.OnStop(func() { t.Error("disarmed stream was closed") })
	finish()
	child, err := parent.Reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	child.Release()
	e.capacity.mu.Lock()
	e.capacity.stopLocked()
	e.capacity.mu.Unlock()
	if !parent.Stopping() {
		t.Fatal("admitted lease did not see the capacity stop")
	}
	parent.Release()
	select {
	case <-e.capacity.Drained():
	default:
		t.Fatal("capacity did not drain after the final release")
	}
}

func TestCapacityRetirementRefusesOutstandingAdmission(t *testing.T) {
	capacity := NewCapacity(8192)
	e, dir, signer := newIncrementalRun(t, capacity)
	if got := e.Capacity(); got != capacity {
		t.Fatal("emitter did not use the supplied coordinator")
	}
	activity := Activity{Class: "fixture", Direction: "out", ID: "unit"}
	lease, err := e.Reserve(1, ActivityRecordLimit(len(activity.Class), len(activity.ID)))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	record, err := e.PrepareActivity(activity, lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Append(true); err != nil {
		t.Fatal(err)
	}
	if err := e.EmitCloseIfIdle(); !errors.Is(err, ErrActiveAdmission) {
		t.Fatalf("retirement with spent lease = %v, want %v", err, ErrActiveAdmission)
	}
	lease.Release()
	if err := e.EmitCloseIfIdle(); err != nil {
		t.Fatal(err)
	}
	if head, err := VerifyRun(dir, incrementalRunID, signer); err != nil || head.RecordCount != 3 {
		t.Fatalf("verified retirement head=%+v error=%v", head, err)
	}
	if err := e.EmitCloseIfIdle(); err == nil || err.Error() != "native AEL run is closed" {
		t.Fatalf("second retirement = %v", err)
	}
}

func TestCapacityAdmissionRefusesUnhealthyEmitter(t *testing.T) {
	e, _, _ := newIncrementalRun(t)
	t.Cleanup(func() {
		if err := e.Abort(); err != nil {
			t.Error(err)
		}
	})
	e.fileSync = func(*os.File) error { return io.ErrClosedPipe }
	activity := Activity{Class: "fixture", Direction: "out", ID: "unit"}
	if err := e.EmitActivity(activity, true); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("durable append = %v, want %v", err, io.ErrClosedPipe)
	}
	if lease, err := e.Reserve(1, 1000); lease != nil || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("admission lease=%v error=%v", lease, err)
	}
}

func TestCapacityWakeCutoffCanBeDisarmedDuringGrace(t *testing.T) {
	var absent *Capacity
	absent.OnStopAfter(0, func() { t.Error("absent capacity ran the cutoff") })()
	synctest.Test(t, func(t *testing.T) {
		const grace = time.Second
		c := NewCapacity(8192)
		reached := make(chan struct{})
		disarm := c.OnStopAfter(grace, func() { close(reached) })
		c.mu.Lock()
		c.stopLocked()
		c.mu.Unlock()
		synctest.Wait()
		select {
		case <-reached:
			t.Fatal("cutoff fired at the start of grace")
		default:
		}
		disarm()
		<-time.After(grace)
		synctest.Wait()
		select {
		case <-reached:
			t.Fatal("disarmed cutoff fired")
		default:
		}

		cutoff := make(chan time.Time, 1)
		join := c.OnStopAfter(grace, func() { cutoff <- time.Now() })
		defer join()
		synctest.Wait()
		select {
		case firedAt := <-cutoff:
			if want := c.stoppedAt.Add(grace); !firedAt.Equal(want) {
				t.Fatalf("cutoff at %s, want stop plus grace %s", firedAt, want)
			}
		default:
			t.Fatal("cutoff registered after grace did not run immediately")
		}
	})
}

func TestCapacityRefusesTimestampOutsideRFC3339(t *testing.T) {
	e, dir, signer := newIncrementalRun(t)
	now := e.now
	e.now = func() time.Time { return time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC) }
	activity := Activity{Class: "fixture", Direction: "out", ID: "unit"}
	if err := e.EmitActivity(activity, true); err == nil || err.Error() != "native AEL timestamp is outside the RFC3339 year range" {
		t.Fatalf("activity timestamp refusal = %v", err)
	}
	e.now = now
	if err := e.EmitClose(); err != nil {
		t.Fatal(err)
	}
	if head, err := VerifyRun(dir, incrementalRunID, signer); err != nil || head.RecordCount != 2 {
		t.Fatalf("verified head after timestamp refusal=%+v error=%v", head, err)
	}
}
