// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"strings"
	"testing"
	"time"
)

// A stall callback that started before its read returned can run during a
// later read. It must cancel only a read that has itself waited the window.
func TestStallBoundBodyIgnoresStaleCallback(t *testing.T) {
	const stall = time.Minute
	cancelled := 0
	b := &stallBoundBody{
		ReadCloser: io.NopCloser(strings.NewReader("")),
		cancel:     func() { cancelled++ },
		stall:      stall,
	}

	b.expire() // no read armed
	if cancelled != 0 {
		t.Fatal("callback with no read in progress cancelled the request")
	}

	b.armed, b.armedAt = true, time.Now() // a later read just started
	b.expire()
	if cancelled != 0 {
		t.Fatal("stale callback cancelled a read that has not waited the window")
	}

	b.armedAt = time.Now().Add(-stall - time.Second) // that read has now stalled
	b.expire()
	if cancelled != 1 {
		t.Fatalf("stalled read not cancelled: cancels=%d", cancelled)
	}
}
