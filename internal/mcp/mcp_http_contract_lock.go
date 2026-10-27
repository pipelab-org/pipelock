// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"sync"
)

// contractLock orders a principal's tools/list responses against its
// current-protocol calls, like sync.RWMutex: a list holds it exclusively, calls
// share it, and a waiting list holds back new calls so a stream of calls
// cannot starve it. Unlike sync.RWMutex, every wait also ends when the
// request's context does, so a client that disconnects while a slow list holds
// the lock does not leave its handler blocked. The zero value is ready to use.
type contractLock struct {
	mu             sync.Mutex
	readers        int
	writer         bool
	waitingWriters int
	changed        chan struct{}
}

// Lock acquires the lock exclusively, or returns the context's error.
func (l *contractLock) Lock(ctx context.Context) error {
	registered := false
	for {
		l.mu.Lock()
		if !l.writer && l.readers == 0 {
			l.writer = true
			if registered {
				l.waitingWriters--
			}
			l.mu.Unlock()
			return nil
		}
		if !registered {
			l.waitingWriters++
			registered = true
		}
		changed := l.changedLocked()
		l.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			l.mu.Lock()
			l.waitingWriters--
			// Calls held back by this writer may proceed now.
			l.notifyLocked()
			l.mu.Unlock()
			return ctx.Err()
		}
	}
}

// Unlock releases an exclusive hold.
func (l *contractLock) Unlock() {
	l.mu.Lock()
	l.writer = false
	l.notifyLocked()
	l.mu.Unlock()
}

// RLock acquires a shared hold, or returns the context's error.
func (l *contractLock) RLock(ctx context.Context) error {
	for {
		l.mu.Lock()
		if !l.writer && l.waitingWriters == 0 {
			l.readers++
			l.mu.Unlock()
			return nil
		}
		changed := l.changedLocked()
		l.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// RUnlock releases a shared hold.
func (l *contractLock) RUnlock() {
	l.mu.Lock()
	l.readers--
	if l.readers == 0 {
		l.notifyLocked()
	}
	l.mu.Unlock()
}

func (l *contractLock) changedLocked() chan struct{} {
	if l.changed == nil {
		l.changed = make(chan struct{})
	}
	return l.changed
}

// notifyLocked wakes every waiter to re-check the state.
func (l *contractLock) notifyLocked() {
	if l.changed != nil {
		close(l.changed)
		l.changed = nil
	}
}
