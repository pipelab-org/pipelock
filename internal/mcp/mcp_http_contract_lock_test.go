// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func lockResult(fn func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	return done
}

// requireBlocked gives the waiter time to reach the lock before concluding
// it waits; checking at once could pass before the goroutine even ran.
func requireBlocked(t *testing.T, done <-chan error, what string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("%s did not wait: %v", what, err)
	case <-time.After(testwait.Deadline(50 * time.Millisecond)):
	}
}

func requireResult(t *testing.T, done <-chan error, want error, what string) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("%s returned %v, want %v", what, err, want)
		}
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatalf("%s did not return", what)
	}
}

func TestContractLock_CallWaitEndsWithContext(t *testing.T) {
	var l contractLock
	if err := l.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	call := lockResult(func() error { return l.RLock(ctx) })
	requireBlocked(t, call, "call behind a held list")
	cancel()
	requireResult(t, call, context.Canceled, "cancelled call")
	l.Unlock()
	if err := l.RLock(context.Background()); err != nil {
		t.Fatalf("call after list released: %v", err)
	}
	l.RUnlock()
}

func TestContractLock_WaitingListHoldsBackNewCalls(t *testing.T) {
	var l contractLock
	if err := l.RLock(context.Background()); err != nil {
		t.Fatal(err)
	}
	list := lockResult(func() error { return l.Lock(context.Background()) })
	testwait.For(t, 5*time.Second, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.waitingWriters == 1
	}, "list registered as waiting")
	call := lockResult(func() error { return l.RLock(context.Background()) })
	requireBlocked(t, call, "new call behind a waiting list")
	l.RUnlock()
	requireResult(t, list, nil, "list after the earlier call released")
	requireBlocked(t, call, "call while the list holds the lock")
	l.Unlock()
	requireResult(t, call, nil, "call after the list released")
	l.RUnlock()
}

func TestContractLock_CancelledListReleasesHeldBackCalls(t *testing.T) {
	var l contractLock
	if err := l.RLock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	list := lockResult(func() error { return l.Lock(ctx) })
	testwait.For(t, 5*time.Second, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.waitingWriters == 1
	}, "list registered as waiting")
	call := lockResult(func() error { return l.RLock(context.Background()) })
	requireBlocked(t, call, "call behind a waiting list")
	cancel()
	requireResult(t, list, context.Canceled, "cancelled list")
	requireResult(t, call, nil, "call after the waiting list gave up")
	l.RUnlock()
	l.RUnlock()
	if err := l.Lock(context.Background()); err != nil {
		t.Fatalf("list after every call released: %v", err)
	}
	l.Unlock()
}

func TestContractLock_ListsExcludeEachOther(t *testing.T) {
	var l contractLock
	if err := l.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	requireResult(t, lockResult(func() error { return l.Lock(ctx) }), context.DeadlineExceeded, "second list")
	l.Unlock()
}

func TestContractLock_MutualExclusionUnderLoad(t *testing.T) {
	var l contractLock
	var readers, writers atomic.Int32
	var violations atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(write bool) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if write {
					if err := l.Lock(context.Background()); err != nil {
						violations.Add(1)
						return
					}
					if writers.Add(1) != 1 || readers.Load() != 0 {
						violations.Add(1)
					}
					writers.Add(-1)
					l.Unlock()
					continue
				}
				if err := l.RLock(context.Background()); err != nil {
					violations.Add(1)
					return
				}
				readers.Add(1)
				if writers.Load() != 0 {
					violations.Add(1)
				}
				readers.Add(-1)
				l.RUnlock()
			}
		}(i%4 == 0)
	}
	wg.Wait()
	if got := violations.Load(); got != 0 {
		t.Fatalf("observed %d exclusion violations", got)
	}
}
