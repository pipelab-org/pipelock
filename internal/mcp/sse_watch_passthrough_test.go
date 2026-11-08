// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type watchCountingFlusher struct{ n int }

func (f *watchCountingFlusher) Flush() { f.n++ }

type watchFailingWriter struct {
	err   error
	short bool
}

func (w watchFailingWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, w.err
}

type watchErrReader struct {
	data []byte
	err  error
}

func (r *watchErrReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

type watchUninspected struct{ bytes int64 }

func (u *watchUninspected) record(_, _, action string, n int64, enforced bool) {
	if action == "uninspected" && !enforced {
		u.bytes += n
	}
}

const watchSSEStream = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n" +
	"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"

func TestWatchSSEPassthroughRawCopiesBytes(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	var seen watchUninspected
	f := &watchCountingFlusher{}
	err := ScanGenericSSEStreamWithOptions(context.Background(), strings.NewReader(watchSSEStream), &out, f, nil, nil,
		GenericSSEScanOptions{WatchOnly: true, OnWatchOnly: seen.record})
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != watchSSEStream {
		t.Fatalf("output changed: %q", out.String())
	}
	if seen.bytes != int64(len(watchSSEStream)) {
		t.Fatalf("uninspected bytes = %d, want %d", seen.bytes, len(watchSSEStream))
	}
	if f.n == 0 {
		t.Fatal("stream was never flushed")
	}
}

func TestWatchSSEPassthroughRawErrors(t *testing.T) {
	t.Parallel()
	writeErr := errors.New("client gone")
	readErr := errors.New("upstream reset")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name string
		ctx  context.Context
		body io.Reader
		w    io.Writer
		want error
	}{
		{"write error", context.Background(), strings.NewReader(watchSSEStream), watchFailingWriter{err: writeErr}, writeErr},
		{"short write", context.Background(), strings.NewReader(watchSSEStream), watchFailingWriter{short: true}, io.ErrShortWrite},
		{"read error", context.Background(), &watchErrReader{data: []byte("data: x\n"), err: readErr}, io.Discard, readErr},
		{"canceled", canceled, strings.NewReader(watchSSEStream), io.Discard, context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := passthroughWatchSSE(tc.ctx, tc.body, tc.w, nil, nil, GenericSSEScanOptions{WatchOnly: true})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestWatchSSEPassthroughEventsDeliverAfterObservation(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	var order []string
	opts := GenericSSEScanOptions{
		WatchOnly: true,
		WatchEvent: func(event []byte) error {
			order = append(order, "watch:"+string(bytes.TrimSpace(event))[:10])
			if out.Len() == 0 && len(order) > 1 {
				t.Fatal("second event observed before the first was written")
			}
			return nil
		},
		WatchEventDelivered: func() { order = append(order, "delivered") },
	}
	f := &watchCountingFlusher{}
	if err := ScanGenericSSEStreamWithOptions(context.Background(), strings.NewReader(watchSSEStream), &out, f, nil, nil, opts); err != nil {
		t.Fatal(err)
	}
	if out.String() != watchSSEStream {
		t.Fatalf("output changed: %q", out.String())
	}
	if len(order) != 4 || order[1] != "delivered" || order[3] != "delivered" {
		t.Fatalf("order = %v", order)
	}
	if f.n < 2 {
		t.Fatalf("flushes = %d, want one per event", f.n)
	}
}

// A retained floor reported by the observer must stop the event before any of
// its bytes reach the client.
func TestWatchSSEPassthroughEventsFloorStopsBeforeWrite(t *testing.T) {
	t.Parallel()
	floor := errors.New("core credential floor")
	var out bytes.Buffer
	delivered := 0
	err := passthroughWatchSSE(context.Background(), strings.NewReader(watchSSEStream), &out, nil, nil, GenericSSEScanOptions{
		WatchOnly:           true,
		WatchEvent:          func([]byte) error { return floor },
		WatchEventDelivered: func() { delivered++ },
	})
	if !errors.Is(err, floor) {
		t.Fatalf("err = %v, want floor", err)
	}
	if out.Len() != 0 || delivered != 0 {
		t.Fatalf("floor event leaked: %q delivered=%d", out.String(), delivered)
	}
}

func TestWatchSSEPassthroughEventsErrors(t *testing.T) {
	t.Parallel()
	writeErr := errors.New("client gone")
	readErr := errors.New("upstream reset")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	watch := func([]byte) error { return nil }
	cases := []struct {
		name string
		ctx  context.Context
		body io.Reader
		w    io.Writer
		want error
	}{
		{"write error", context.Background(), strings.NewReader(watchSSEStream), watchFailingWriter{err: writeErr}, writeErr},
		{"short write", context.Background(), strings.NewReader(watchSSEStream), watchFailingWriter{short: true}, io.ErrShortWrite},
		{"read error", context.Background(), &watchErrReader{data: []byte("data: x\n"), err: readErr}, io.Discard, readErr},
		{"canceled", canceled, strings.NewReader(watchSSEStream), io.Discard, context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var seen watchUninspected
			err := passthroughWatchSSE(tc.ctx, tc.body, tc.w, nil, nil,
				GenericSSEScanOptions{WatchOnly: true, WatchEvent: watch, OnWatchOnly: seen.record})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// An event larger than the inspection bound is delivered unchanged and counted
// as uninspected instead of being observed.
func TestWatchSSEPassthroughEventsOversizedUninspected(t *testing.T) {
	t.Parallel()
	big := "data: " + strings.Repeat("a", DefaultGenericSSEMaxEventBytes+16) + "\n\n"
	stream := big + watchSSEStream
	var out bytes.Buffer
	var seen watchUninspected
	observed := 0
	err := passthroughWatchSSE(context.Background(), strings.NewReader(stream), &out, nil, nil, GenericSSEScanOptions{
		WatchOnly:   true,
		WatchEvent:  func([]byte) error { observed++; return nil },
		OnWatchOnly: seen.record,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != stream {
		t.Fatal("oversized stream changed in transit")
	}
	if observed != 2 {
		t.Fatalf("observed %d events, want the 2 bounded events", observed)
	}
	if seen.bytes < int64(len(big)) {
		t.Fatalf("uninspected bytes = %d, want at least %d", seen.bytes, len(big))
	}
}
