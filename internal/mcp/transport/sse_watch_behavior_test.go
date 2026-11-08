// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

func TestWatchSSEPreservesEventWireAndMetadata(t *testing.T) {
	first := ": keepalive\r\nid: event-1\r\nevent: update\r\nretry: 2500\r\ndata: first\r\ndata:second\r\ndata\r\n\r\n"
	second := "id: ignored\x00id\ndata: last"
	r := NewWatchSSEReader(strings.NewReader(first+second), 0, nil)
	msg, err := r.ReadMessage()
	if err != nil || string(msg) != "first\nsecond\n" || string(r.RawMessage()) != first || r.Uninspected() {
		t.Fatalf("first event: data=%q raw=%q uninspected=%v err=%v", msg, r.RawMessage(), r.Uninspected(), err)
	}
	if r.LastEventID() != "event-1" || r.LastEventType() != "update" || r.LastRetry() != "2500" {
		t.Fatal("event metadata lost")
	}
	msg, err = r.ReadMessage()
	if err != nil || string(msg) != "last" || string(r.RawMessage()) != second {
		t.Fatalf("EOF event changed: data=%q raw=%q err=%v", msg, r.RawMessage(), err)
	}
	if r.LastEventID() != "event-1" || r.LastEventType() != "" || r.LastRetry() != "" {
		t.Fatal("event metadata leaked or invalid ID replaced resume ID")
	}
	if _, err := r.ReadMessage(); !errors.Is(err, io.EOF) {
		t.Fatalf("stream end=%v", err)
	}
	ordinary := NewSSEReader(strings.NewReader(""))
	if ordinary.RawMessage() != nil || ordinary.Uninspected() {
		t.Fatal("ordinary reader exposes watch-only state")
	}
}

func TestWatchSSEOversizedEventStreamsThenResumes(t *testing.T) {
	first := ": queued\r\ndata: " + strings.Repeat("x", 8192) + "\r\n\r\n"
	second := "data: next\n\n"
	var forwarded bytes.Buffer
	r := NewWatchSSEReader(strings.NewReader(first+second), 32, func(p []byte) error { _, err := forwarded.Write(p); return err })
	msg, err := r.ReadMessage()
	if err != nil || len(msg) != 0 || !r.Uninspected() || len(r.RawMessage()) != 0 || forwarded.String() != first {
		t.Fatalf("oversized event changed: data=%d raw=%d forwarded=%d err=%v", len(msg), len(r.RawMessage()), forwarded.Len(), err)
	}
	msg, err = r.ReadMessage()
	if err != nil || string(msg) != "next" || r.Uninspected() || string(r.RawMessage()) != second {
		t.Fatalf("next event not inspected: data=%q raw=%q err=%v", msg, r.RawMessage(), err)
	}
	if _, err := r.ReadMessage(); !errors.Is(err, io.EOF) {
		t.Fatalf("stream end=%v", err)
	}
}

func TestWatchSSEForwardFailureStopsDelivery(t *testing.T) {
	prefix := ": queued\n"
	wire := prefix + "data: " + strings.Repeat("x", 64) + "\n\n"
	failure := errors.New("downstream unavailable")
	for _, failOn := range []int{1, 2} {
		t.Run(strconv.Itoa(failOn), func(t *testing.T) {
			calls := 0
			var forwarded bytes.Buffer
			r := NewWatchSSEReader(strings.NewReader(wire), 16, func(p []byte) error {
				calls++
				if calls == failOn {
					return failure
				}
				_, err := forwarded.Write(p)
				return err
			})
			if _, err := r.ReadMessage(); !errors.Is(err, failure) || calls != failOn {
				t.Fatalf("forward failure=%v calls=%d", err, calls)
			}
			want := ""
			if failOn == 2 {
				want = prefix
			}
			if forwarded.String() != want {
				t.Fatalf("bytes delivered after failure: %q", forwarded.String())
			}
		})
	}
	missing := NewWatchSSEReader(strings.NewReader(wire), 16, nil)
	if _, err := missing.ReadMessage(); err == nil || !strings.Contains(err.Error(), "callback missing") {
		t.Fatalf("missing passthrough callback error=%v", err)
	}
}

type watchSSEFailureReader struct{ err error }

func (r watchSSEFailureReader) Read([]byte) (int, error) { return 0, r.err }

func TestWatchSSEReadFailureDoesNotYieldPartialEvent(t *testing.T) {
	failure := errors.New("upstream interrupted")
	r := NewWatchSSEReader(io.MultiReader(strings.NewReader("data: partial"), watchSSEFailureReader{failure}), 0, nil)
	msg, err := r.ReadMessage()
	if !errors.Is(err, failure) || len(msg) != 0 {
		t.Fatalf("partial event released: data=%q err=%v", msg, err)
	}
}
