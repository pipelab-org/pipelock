// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"sync"
	"testing"
)

// receiptProducerStops is the set of listener drains for one test.
// A handler appends the terminal receipt outcome after it flushes the
// response, so closing the writer at the client's next line races that append.
// Draining the listener first waits until those handlers return.
type receiptProducerStops struct {
	mu      sync.Mutex
	stops   []func()
	done    bool
	cleanup bool
}

var mcpReceiptProducers sync.Map // *testing.T -> *receiptProducerStops

// registerMCPReceiptProducerStop remembers a drain that receipt readers run
// before they close the v3 writer. The drain also runs from test cleanup, so a
// test that never reads receipts still stops its listener.
func registerMCPReceiptProducerStop(t *testing.T, stop func()) {
	t.Helper()
	if stop == nil {
		return
	}
	v, _ := mcpReceiptProducers.LoadOrStore(t, &receiptProducerStops{})
	set := v.(*receiptProducerStops)
	set.mu.Lock()
	if !set.cleanup {
		set.cleanup = true
		t.Cleanup(func() {
			drainMCPReceiptProducers(t)
			mcpReceiptProducers.Delete(t)
		})
	}
	if set.done {
		set.mu.Unlock()
		stop()
		return
	}
	set.stops = append(set.stops, stop)
	set.mu.Unlock()
}

// drainMCPReceiptProducers runs each registered drain once. A second call,
// including the cleanup after a reader already drained, does nothing.
func drainMCPReceiptProducers(t *testing.T) {
	t.Helper()
	v, ok := mcpReceiptProducers.Load(t)
	if !ok {
		return
	}
	set := v.(*receiptProducerStops)
	set.mu.Lock()
	if set.done {
		set.mu.Unlock()
		return
	}
	stops := set.stops
	set.stops = nil
	set.done = true
	set.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

// listenProxyDrain stops a listener and waits until RunHTTPListenerProxy
// returns. Receipt readers and test cleanup share one wait, so the done
// channel is received only once.
func listenProxyDrain(t *testing.T, release func(), done <-chan error) {
	t.Helper()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			release()
			waitForListenerProxyStop(t, done)
		})
	}
	registerMCPReceiptProducerStop(t, stop)
	t.Cleanup(stop)
}
