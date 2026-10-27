// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type coreConductorCloser struct {
	closes atomic.Int32
	err    error
}

func (c *coreConductorCloser) Close() error {
	c.closes.Add(1)
	return c.err
}

type coreConductorRunner struct{}

func (coreConductorRunner) Run(context.Context) error { return nil }

func TestCoreConductorLifecycleHelpers(t *testing.T) {
	var calls atomic.Int32
	restore := SetReloadCompletedHookForTest(func() { calls.Add(1) })
	fireReloadCompletedHook()
	got := calls.Load()
	restore()
	if got != 1 {
		t.Fatalf("reload hook calls = %d, want 1", got)
	}
	fireReloadCompletedHook()
	if got := calls.Load(); got != 1 {
		t.Fatalf("reload hook calls after restore = %d, want unchanged 1", got)
	}

	errCloser := &coreConductorCloser{err: errors.New("ignored")}
	closeConductorAuditQueue(errCloser)
	closeConductorAuditQueue(struct{}{})
	if got := errCloser.closes.Load(); got != 1 {
		t.Fatalf("queue close count = %d, want 1", got)
	}

	if (&Server{}).hasConductorRuntime() {
		t.Fatal("empty server must not report conductor runtime")
	}
	if !(&Server{conductorRemoteKill: coreConductorRunner{}}).hasConductorRuntime() {
		t.Fatal("server with conductor runner must report conductor runtime")
	}
	if !(&Server{conductorProducer: &coreConductorCloser{}}).hasConductorRuntime() {
		t.Fatal("server with conductor producer must report conductor runtime")
	}
}

func TestCoreConductorExpireLicensedRuntimeStopsRuntime(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	producer := &coreConductorCloser{}
	queue := &coreConductorCloser{}
	var waited atomic.Bool
	var stderr bytes.Buffer
	s := &Server{
		opts:                ServerOpts{Stderr: &stderr},
		conductorProducer:   producer,
		conductorAuditQueue: queue,
	}
	s.setConductorCancel(cancel)
	s.setConductorWait(func() {
		if ctx.Err() == nil {
			t.Fatal("conductor wait ran before cancellation")
		}
		waited.Store(true)
	})

	s.expireLicensedRuntime()

	if !s.conductorDown.Load() {
		t.Fatal("expiry must mark conductor down")
	}
	if got := producer.closes.Load(); got != 1 {
		t.Fatalf("producer close count = %d, want 1", got)
	}
	if got := queue.closes.Load(); got != 1 {
		t.Fatalf("queue close count = %d, want 1", got)
	}
	if !waited.Load() {
		t.Fatal("expiry teardown must wait for conductor goroutines")
	}
	if !strings.Contains(stderr.String(), "license expired") {
		t.Fatalf("stderr = %q, want license expiry notice", stderr.String())
	}
}

type shutdownAuditRunner struct{ drain func(context.Context) error }

func (shutdownAuditRunner) Run(ctx context.Context) error     { return ctx.Err() }
func (r shutdownAuditRunner) Drain(ctx context.Context) error { return r.drain(ctx) }

func TestConductorShutdownDrainAdmission(t *testing.T) {
	for _, tc := range []struct {
		name    string
		started bool
		revoked bool
	}{
		{name: "started", started: true},
		{name: "construction"},
		{name: "revoked", started: true, revoked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			producer, queue := &coreConductorCloser{}, &coreConductorCloser{}
			var out syncBuffer
			s := &Server{opts: ServerOpts{Stderr: &out}, conductorProducer: producer, conductorAuditQueue: queue}
			var called bool
			s.conductorAudit = shutdownAuditRunner{drain: func(ctx context.Context) error {
				called = true
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > serverShutdownTimeout || ctx.Err() != nil {
					t.Errorf("drain needs a live bounded shutdown context: deadline=%v, err=%v", deadline, ctx.Err())
				}
				if producer.closes.Load() != 1 || queue.closes.Load() != 0 {
					t.Error("drain must follow producer close and precede queue close")
				}
				return errors.New("test upload unavailable")
			}}
			if tc.started {
				s.setConductorWait(func() {})
			}
			s.conductorDown.Store(tc.revoked)
			s.finishConductorAudit()
			s.finishConductorAudit()
			if want := tc.started && !tc.revoked; called != want {
				t.Errorf("drain called=%v, want %v", called, want)
			}
			if called && !out.contains("final conductor audit delivery incomplete") {
				t.Error("failed final drain must report incomplete delivery")
			}
			if producer.closes.Load() != 1 || queue.closes.Load() != 1 {
				t.Error("producer and queue must close exactly once")
			}
		})
	}
}

func TestConductorShutdownDrainRevocationCancelsAndJoins(t *testing.T) {
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	queue := &coreConductorCloser{}
	s := &Server{conductorAuditQueue: queue}
	s.setConductorWait(func() {})
	s.conductorAudit = shutdownAuditRunner{drain: func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
		return ctx.Err()
	}}
	finished := make(chan struct{})
	go func() {
		s.finishConductorAudit()
		close(finished)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("final drain did not start")
	}
	revoked := make(chan struct{})
	go func() {
		s.teardownConductor("test revoke during shutdown")
		close(revoked)
	}()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("revocation did not cancel the final drain")
	}
	if queue.closes.Load() != 0 {
		t.Error("queue closed before drain joined")
	}
	select {
	case <-revoked:
		t.Error("revocation returned before drain joined")
	default:
	}
	close(release)
	for _, done := range []<-chan struct{}{finished, revoked} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("shutdown or revocation did not join")
		}
	}
	if queue.closes.Load() != 1 {
		t.Fatal("queue must close exactly once after drain joins")
	}
}
