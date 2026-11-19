// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
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
	if available := e.availableBytes(); available != bound-pending.size {
		t.Fatalf("available=%d, want %d", available, bound-pending.size)
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
	<-closed
	finish()
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
	<-e.capacity.Drained()
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
	<-e.capacity.Drained()
}
