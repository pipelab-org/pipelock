// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gobwas/ws"
)

func collectWatchMessage(t *testing.T, r MessageReader) ([]byte, bool) {
	t.Helper()
	var result []byte
	streamed := false
	for {
		msg, err := r.ReadMessage()
		var chunk *UninspectedMessageChunkError
		if errors.As(err, &chunk) {
			streamed = true
			result = append(result, msg...)
			if chunk.Final {
				return bytes.TrimSuffix(result, []byte("\n")), streamed
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		return append(result, msg...), streamed
	}
}

func TestWatchBridgeBodyLimits(t *testing.T) {
	for _, size := range []int{16, MaxLineSize, MaxLineSize + 1, MaxLineSize + 32768} {
		data := strings.Repeat("x", size)
		reader := &WatchBodyReader{Body: io.NopCloser(strings.NewReader(data))}
		got, streamed := collectWatchMessage(t, reader)
		if string(got) != data || streamed != (size > MaxLineSize) {
			t.Fatalf("size=%d output=%d streamed=%v", size, len(got), streamed)
		}
	}
}

func TestWatchBridgeSSELimits(t *testing.T) {
	crBoundary := bufio.NewReader(strings.NewReader("")).Size() - len("data: ") - 1
	for _, size := range []int{16, crBoundary, MaxLineSize, MaxLineSize + 1} {
		data := strings.Repeat("x", size)
		reader := newWatchSSEBridgeReader(io.NopCloser(strings.NewReader(": keepalive\r\ndata: " + data + "\r\n\r\n")))
		got, streamed := collectWatchMessage(t, reader)
		if string(got) != data || streamed != (size > MaxLineSize) {
			t.Fatalf("size=%d output=%d streamed=%v", size, len(got), streamed)
		}
	}
}

func TestWatchBridgeWSLimits(t *testing.T) {
	for _, tc := range []struct {
		name       string
		opcode     ws.OpCode
		data       []byte
		wantStream bool
	}{
		{"small", ws.OpText, []byte("hello"), false},
		{"oversized", ws.OpText, bytes.Repeat([]byte("x"), MaxLineSize+1), true},
		{"binary", ws.OpBinary, []byte{1, 2, 3}, true},
		{"utf8", ws.OpText, []byte{0xff, 0xfe}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local, remote := net.Pipe()
			defer func() { _ = local.Close(); _ = remote.Close() }()
			done := make(chan error, 1)
			go func() { done <- ws.WriteFrame(remote, ws.NewFrame(tc.opcode, true, tc.data)) }()
			c := NewWSClientFromConn(local, false)
			c.WatchOnly = func() bool { return true }
			got, streamed := collectWatchMessage(t, c)
			if !bytes.Equal(got, tc.data) || streamed != tc.wantStream {
				t.Fatalf("output=%d streamed=%v", len(got), streamed)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWatchBridgeHTTPStatusPreserved(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusPartialContent, http.StatusBadRequest} {
		body := `{"jsonrpc":"2.0","id":1,"result":"original"}`
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status); _, _ = io.WriteString(w, body) }))
		c := NewHTTPClient(upstream.URL, nil)
		c.WatchOnly = func() bool { return true }
		reader, err := c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		if err != nil {
			upstream.Close()
			t.Fatal(err)
		}
		got, _ := collectWatchMessage(t, reader)
		upstream.Close()
		if string(got) != body {
			t.Fatalf("status %d changed body", status)
		}
	}
}

func TestWatchBridgeBodyWhitespace(t *testing.T) {
	const body = " \t\r\n"
	reader := &WatchBodyReader{Body: io.NopCloser(strings.NewReader(body))}
	got, _ := collectWatchMessage(t, reader)
	if string(got) != body {
		t.Fatalf("whitespace body changed: %q", got)
	}
}
