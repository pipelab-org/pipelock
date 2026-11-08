// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type watchLifecycleBody struct {
	io.Reader
	closed   int
	closeErr error
}

func (b *watchLifecycleBody) Close() error { b.closed++; return b.closeErr }

func TestWatchStdioOrdinaryFramingAndEOF(t *testing.T) {
	for _, enabled := range []func() bool{nil, func() bool { return false }} {
		r := NewWatchStdioReader(strings.NewReader(" \t\n  first  \r\n\n"+strings.Repeat("x", 5000)+"\n \t"), enabled)
		for _, want := range []string{"first", strings.Repeat("x", 5000)} {
			msg, err := r.ReadMessage()
			if err != nil || string(msg) != want {
				t.Fatalf("ordinary framing changed: bytes=%d want=%d err=%v", len(msg), len(want), err)
			}
		}
		if msg, err := r.ReadMessage(); !errors.Is(err, io.EOF) || len(msg) != 0 {
			t.Fatalf("whitespace EOF=%q %v", msg, err)
		}
	}
	for _, wire := range []string{"", "\n", "last"} {
		r := NewWatchStdioReader(strings.NewReader(wire), func() bool { return true })
		msg, err := r.ReadMessage()
		if wire == "" {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("empty EOF=%v", err)
			}
			continue
		}
		if err != nil || string(msg) != strings.TrimSuffix(wire, "\n") {
			t.Fatalf("watch framing=%q err=%v", msg, err)
		}
		if _, err := r.ReadMessage(); !errors.Is(err, io.EOF) {
			t.Fatalf("terminal EOF=%v", err)
		}
	}
}

func TestWatchStdioReadFailuresDoNotReleasePartialMessages(t *testing.T) {
	failure := errors.New("stdin interrupted")
	for _, draining := range []bool{false, true} {
		data := "partial"
		if draining {
			data = strings.Repeat("x", bufio.NewReader(strings.NewReader("")).Size())
		}
		r := NewWatchStdioReader(io.MultiReader(strings.NewReader(data), watchSSEFailureReader{failure}), func() bool { return true })
		r.limit = 16
		if draining {
			msg, err := r.ReadMessage()
			var chunk *UninspectedMessageChunkError
			if !errors.As(err, &chunk) || chunk.Final || string(msg) != data || chunk.Error() != "message exceeds inspection ceiling" {
				t.Fatalf("initial streaming chunk=%d %+v %v", len(msg), chunk, err)
			}
		}
		msg, err := r.ReadMessage()
		if !errors.Is(err, failure) || len(msg) != 0 {
			t.Fatalf("partial failure released bytes: %q err=%v", msg, err)
		}
	}
}

func TestWatchStdioRawWritePreservesDelimitersAndErrors(t *testing.T) {
	var out bytes.Buffer
	writer := NewStdioWriter(&out)
	failure := errors.New("source interrupted")
	err := writer.WithRawMessage(func(w io.Writer) error {
		for _, chunk := range []string{"part", "ial\nnext"} {
			if _, err := io.WriteString(w, chunk); err != nil {
				return err
			}
		}
		return failure
	})
	if !errors.Is(err, failure) || out.String() != "partial\nnext" {
		t.Fatalf("raw write changed bytes=%q err=%v", out.String(), err)
	}
}

func TestWatchBodyLifecycleAndIncompleteResponses(t *testing.T) {
	failure := errors.New("body interrupted")
	body := &watchLifecycleBody{Reader: io.MultiReader(strings.NewReader("partial"), watchSSEFailureReader{failure})}
	r := &WatchBodyReader{Body: body}
	msg, err := r.ReadMessage()
	if !errors.Is(err, failure) || !errors.Is(err, ErrIncompleteResponse) || len(msg) != 0 || body.closed != 1 {
		t.Fatalf("body failure released message=%q closed=%d err=%v", msg, body.closed, err)
	}
	empty := &watchLifecycleBody{Reader: strings.NewReader("")}
	r = &WatchBodyReader{Body: empty}
	for range 2 {
		if msg, err := r.ReadMessage(); !errors.Is(err, io.EOF) || len(msg) != 0 {
			t.Fatalf("empty body=%q err=%v", msg, err)
		}
	}
	if empty.closed != 1 {
		t.Fatalf("empty body close count=%d", empty.closed)
	}
	body = &watchLifecycleBody{Reader: strings.NewReader("opaque"), closeErr: failure}
	r = &WatchBodyReader{Body: body, Uninspected: true, Reason: "unsupported response encoding"}
	msg, err = r.ReadMessage()
	var chunk *UninspectedMessageChunkError
	if !errors.As(err, &chunk) || !chunk.Final || chunk.Error() != r.Reason || string(msg) != "opaque\n" || body.closed != 1 {
		t.Fatalf("opaque body=%q chunk=%+v closed=%d err=%v", msg, chunk, body.closed, err)
	}
	if err := r.Close(); !errors.Is(err, failure) || body.closed != 2 {
		t.Fatalf("explicit body close=%v count=%d", err, body.closed)
	}
}

func TestWatchSSEBridgeDataLinesAndClose(t *testing.T) {
	body := &watchLifecycleBody{Reader: strings.NewReader(": comment\n\ndata\ndata: second\n\n: tail")}
	r := newWatchSSEBridgeReader(body)
	msg, err := r.ReadMessage()
	if err != nil || string(msg) != "\nsecond" {
		t.Fatalf("multiline data changed: %q err=%v", msg, err)
	}
	for range 2 {
		if msg, err := r.ReadMessage(); !errors.Is(err, io.EOF) || len(msg) != 0 {
			t.Fatalf("comment-only EOF=%q err=%v", msg, err)
		}
	}
	if body.closed != 1 {
		t.Fatalf("EOF did not close body once: %d", body.closed)
	}
	failure := errors.New("close failed")
	body.closeErr = failure
	if err := r.Close(); !errors.Is(err, failure) || body.closed != 2 {
		t.Fatalf("explicit close=%v count=%d", err, body.closed)
	}
}

func TestWatchSSEBridgeSplitCarriageReturn(t *testing.T) {
	prefix := strings.Repeat("x", bufio.NewReader(strings.NewReader("")).Size()-len("data: ")-1)
	for _, suffix := range []string{"continued\n\n", ""} {
		body := &watchLifecycleBody{Reader: strings.NewReader("data: " + prefix + "\r" + suffix)}
		r := newWatchSSEBridgeReader(body)
		msg, err := r.ReadMessage()
		want := prefix
		if suffix != "" {
			want += "\rcontinued"
		}
		if err != nil || string(msg) != want {
			t.Fatalf("split CR changed payload: bytes=%d want=%d err=%v", len(msg), len(want), err)
		}
		if _, err := r.ReadMessage(); !errors.Is(err, io.EOF) {
			t.Fatalf("stream end=%v", err)
		}
		if body.closed != 1 {
			t.Fatalf("body left open: count=%d", body.closed)
		}
	}
}

func TestWatchSSEBridgeReadFailureClosesWithoutPartialEvent(t *testing.T) {
	failure := errors.New("SSE interrupted")
	body := &watchLifecycleBody{Reader: io.MultiReader(strings.NewReader("data: partial"), watchSSEFailureReader{failure})}
	r := newWatchSSEBridgeReader(body)
	msg, err := r.ReadMessage()
	if !errors.Is(err, failure) || len(msg) != 0 || body.closed != 1 {
		t.Fatalf("partial SSE released: %q closed=%d err=%v", msg, body.closed, err)
	}
}

func TestWatchHTTPSendStreamPreservesRequest(t *testing.T) {
	const original = "  {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"} \n"
	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		seen <- string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "response")
	}))
	defer server.Close()
	client := NewHTTPClient(server.URL, nil)
	client.WatchOnly = func() bool { return true }
	r, err := client.SendStream(t.Context(), strings.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := r.ReadMessage()
	if err != nil || string(msg) != "response" || <-seen != original {
		t.Fatalf("stream bridge changed request or response=%q err=%v", msg, err)
	}
	if _, err := r.ReadMessage(); !errors.Is(err, io.EOF) {
		t.Fatalf("response EOF=%v", err)
	}
}

func TestWatchHTTPGETResponseRepresentations(t *testing.T) {
	for _, tc := range []struct {
		name, content, encoding, body, want string
		status                              int
		streamed                            bool
	}{
		{"SSE", "text/event-stream", "", "data: event\n\n", "event", http.StatusOK, false},
		{"opaque", "application/octet-stream", "", "opaque", "opaque", http.StatusOK, true},
		{"encoded SSE", "text/event-stream", "br", "opaque", "opaque", http.StatusOK, true},
		{"unsupported", "text/event-stream", "", "", "", http.StatusMethodNotAllowed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("stream did not use GET")
				}
				w.Header().Set("Content-Type", tc.content)
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := NewHTTPClient(server.URL, nil)
			client.WatchOnly = func() bool { return true }
			r, err := client.OpenGETStream(t.Context())
			if tc.status == http.StatusMethodNotAllowed {
				if !errors.Is(err, ErrStreamNotSupported) {
					t.Fatalf("unsupported stream=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, streamed := collectWatchMessage(t, r)
			if string(got) != tc.want || streamed != tc.streamed {
				t.Fatalf("response=%q streamed=%v", got, streamed)
			}
			if closer, ok := r.(io.Closer); ok {
				if err := closer.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestWatchHTTPInitializationAndInvalidToken(t *testing.T) {
	for _, valid := range []bool{false, true} {
		name := "invalid"
		if valid {
			name = "valid"
		}
		t.Run(name, func(t *testing.T) {
			seen := make(chan string, 2)
			token := "bad"
			if valid {
				token = strings.Repeat("a", 43)
			}
			response := `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get(mcpProtocolVersionHeader)
				w.Header().Set(pipelockSessionTokenHeader, token)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, response)
			}))
			defer server.Close()
			client := NewHTTPClient(server.URL, nil)
			client.WatchOnly = func() bool { return true }
			r, err := client.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
			if !valid {
				if !errors.Is(err, ErrInvalidPipelockSessionToken) || r != nil {
					t.Fatalf("invalid token response admitted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			msg, err := r.ReadMessage()
			if err != nil || string(msg) != response {
				t.Fatalf("initialization response=%q err=%v", msg, err)
			}
			if got := <-seen; got != "" {
				t.Fatalf("first request inherited protocol=%q", got)
			}
			r, err = client.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
			if err != nil {
				t.Fatal(err)
			}
			drain(t, r)
			if got := <-seen; got != protocolTestVersion {
				t.Fatalf("initialization failed to commit protocol: %q", got)
			}
		})
	}
}

func TestWatchHTTPSessionCommitFailureWithholdsMessage(t *testing.T) {
	failure := errors.New("session admission unavailable")
	body := &watchLifecycleBody{Reader: strings.NewReader("response")}
	r := &sessionResponseReader{reader: &WatchBodyReader{Body: body}, commit: func() error { return failure }}
	msg, err := r.ReadMessage()
	if !errors.Is(err, failure) || len(msg) != 0 || r.done {
		t.Fatalf("failed session admission released message=%q done=%v err=%v", msg, r.done, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if body.closed == 0 {
		t.Fatal("aborted response body left open")
	}
}
