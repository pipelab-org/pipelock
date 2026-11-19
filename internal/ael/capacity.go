// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

const closeRecordKind = "close"

// ErrCapacity means the run is closing so its native evidence stays verifiable.
var ErrCapacity = errors.New("native AEL stream reached capacity; restart required")

// ErrRecordTooLarge identifies an encoded line above its permitted size.
var ErrRecordTooLarge = errors.New("native AEL record exceeds limit")

// ErrInvalidLease identifies an emission outside its admission reservation.
var ErrInvalidLease = errors.New("native AEL record has no available reservation")

// Capacity coordinates admission and drain across all streams in a run.
type Capacity struct {
	mu        sync.Mutex
	limit     int64
	stopped   chan struct{}
	drained   chan struct{}
	stopping  bool
	stoppedAt time.Time
	active    int
}

// NewCapacity uses the verifier ceiling. A smaller positive limit is used by
// runtime tests to exercise the same stop without writing hundreds of MiB.
func NewCapacity(limit int64) *Capacity {
	if limit <= 0 || limit > maxVerifyStreamBytes {
		limit = maxVerifyStreamBytes
	}
	return &Capacity{limit: limit, stopped: make(chan struct{}), drained: make(chan struct{})}
}

// Stopped closes when any shard refuses a new obligation.
func (c *Capacity) Stopped() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.stopped
}

// Drained closes when the last admitted obligation is released after a stop.
func (c *Capacity) Drained() <-chan struct{} { return c.drained }

func (c *Capacity) stopLocked() {
	if c.stopping {
		return
	}
	c.stopping = true
	c.stoppedAt = time.Now()
	close(c.stopped)
	if c.active == 0 {
		close(c.drained)
	}
}

// Lease holds worst-case encoded bytes for an admitted unit. Both the lease
// and the stream's byte counters are guarded by the stream mutex.
type Lease struct {
	emitter     *Emitter
	remaining   int64
	recordLimit int64
	released    bool
}

// Reserve admits a unit that may emit at most records records, with a bound on
// each complete encoded line. The first refusal stops admission on every shard.
func (e *Emitter) Reserve(records int, recordLimit int64) (*Lease, error) {
	if e == nil {
		return nil, nil
	}
	if records < 1 || recordLimit < 1 || recordLimit > maxVerifyRecordBytes {
		return nil, errors.New("invalid native AEL reservation")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastErr != nil {
		return nil, fmt.Errorf("native AEL emitter unhealthy: %w", e.lastErr)
	}
	if !e.opened || e.closed {
		return nil, errors.New("native AEL run is not active")
	}
	c := e.capacity
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopping || int64(records) > e.availableBytes()/recordLimit {
		c.stopLocked()
		return nil, ErrCapacity
	}
	size := int64(records) * recordLimit
	e.reserved += size
	c.active++
	return &Lease{emitter: e, remaining: size, recordLimit: recordLimit}, nil
}

// Reserve admits another unit on the same stream as this lease.
func (l *Lease) Reserve(records int) (*Lease, error) {
	if l == nil {
		return nil, nil
	}
	return l.emitter.Reserve(records, l.recordLimit)
}

// Split transfers slots to a separately settled part of an admitted unit.
// The run may already be stopping. No new bytes are reserved.
func (l *Lease) Split(records int) (*Lease, error) {
	if l == nil {
		return nil, nil
	}
	e := l.emitter
	e.mu.Lock()
	defer e.mu.Unlock()
	if l.released || records <= 0 || int64(records) > l.remaining/l.recordLimit {
		return nil, ErrInvalidLease
	}
	size := int64(records) * l.recordLimit
	l.remaining -= size
	e.capacity.mu.Lock()
	e.capacity.active++
	e.capacity.mu.Unlock()
	return &Lease{emitter: e, remaining: size, recordLimit: l.recordLimit}, nil
}

// Stopped closes when the run stops admitting new work.
func (l *Lease) Stopped() <-chan struct{} {
	if l == nil {
		return nil
	}
	return l.emitter.capacity.Stopped()
}

// OnStop runs closeStream when the run stops admitting work. The returned
// function disarms the callback or joins it if it is already running.
func (l *Lease) OnStop(closeStream func()) func() {
	return l.OnStopAfter(0, closeStream)
}

// OnStopAfter runs cutoff after the run stops and grace elapses. The returned
// function disarms either wait and joins a cutoff that has already started.
func (l *Lease) OnStopAfter(grace time.Duration, cutoff func()) func() {
	if l == nil {
		return func() {}
	}
	return l.emitter.capacity.OnStopAfter(grace, cutoff)
}

// OnStopAfter schedules a cutoff relative to the shared capacity stop.
func (c *Capacity) OnStopAfter(grace time.Duration, cutoff func()) func() {
	if c == nil {
		return func() {}
	}
	finished := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-c.Stopped():
		case <-stop:
			return
		}
		if grace > 0 {
			timer := time.NewTimer(time.Until(c.stoppedAt.Add(grace)))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-stop:
				return
			}
		}
		cutoff()
	}()
	return func() {
		close(stop)
		<-finished
	}
}

// Stopping reports whether the run has stopped admitting work.
func (l *Lease) Stopping() bool {
	select {
	case <-l.Stopped():
		return true
	default:
		return false
	}
}

// Release returns the unused record slots to the writer and settles the unit.
func (l *Lease) Release() {
	if l == nil {
		return
	}
	e := l.emitter
	e.mu.Lock()
	defer e.mu.Unlock()
	if l.released {
		return
	}
	l.released = true
	e.reserved -= l.remaining
	l.remaining = 0
	if e.prepared == nil || e.prepared.lease != l {
		e.capacity.settle()
	}
}

func (c *Capacity) settle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active--
	if c.stopping && c.active == 0 {
		close(c.drained)
	}
}

func (e *Emitter) availableBytes() int64 {
	available := e.capacity.limit - e.written - e.reserved - maxCloseBytes
	if e.prepared != nil && e.prepared.kind != closeRecordKind && e.prepared.lease == nil {
		available -= e.prepared.size
	}
	return available
}

// The close has only fixed-width fields except seq, count and timestamp.
// The largest safe sequence/count has 16 digits and RFC3339Nano has at
// most 30 bytes for a UTC timestamp in the RFC3339 year range.
var maxCloseBytes = int64(recordLineSize(len(`{"count":9007199254740991,"head":"` + zeroHash +
	`","key":"` + zeroHash + `","prev":"` + zeroHash + `","recorder":"` + recorderID +
	`","run":"00000000000000000000000000000000","seq":9007199254740991,"ts":"9999-12-31T23:59:59.999999999Z","type":"close","v":1}`)))

// ActivityRecordLimit bounds a compact activity line with a class of at most
// classBytes and an ID of at most idBytes. JSON can escape each byte as six
// ASCII characters. The common fields use the largest safe sequence and the
// longest UTC timestamp accepted by the encoder.
func ActivityRecordLimit(classBytes, idBytes int) int64 {
	common := len(`{"event":{"class":"","dir":"internal","id":""},"key":"` + zeroHash +
		`","prev":"` + zeroHash + `","recorder":"` + recorderID +
		`","run":"00000000000000000000000000000000","seq":9007199254740991,"ts":"9999-12-31T23:59:59.999999999Z","type":"activity","v":1}`)
	return int64(recordLineSize(common + 6*(classBytes+idBytes)))
}

func recordLineSize(payloadBytes int) int {
	return base64.RawURLEncoding.EncodedLen(payloadBytes) + 1 + base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) + 1
}

// checkRecordSpace is called before signing and advancing the record chain.
func (e *Emitter) checkRecordSpace(kind string, size int64, lease *Lease) error {
	if size > maxVerifyRecordBytes {
		return ErrRecordTooLarge
	}
	if kind == closeRecordKind {
		if size > maxCloseBytes || e.written+size > e.capacity.limit {
			return ErrCapacity
		}
		return nil
	}
	if lease != nil {
		if lease.emitter != e || lease.released || lease.remaining < lease.recordLimit {
			return ErrInvalidLease
		}
		if size > lease.recordLimit {
			return fmt.Errorf("%w: reservation allows %d bytes", ErrRecordTooLarge, lease.recordLimit)
		}
		return nil
	}
	c := e.capacity
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopping || size > e.availableBytes() {
		c.stopLocked()
		return ErrCapacity
	}
	c.active++
	return nil
}
