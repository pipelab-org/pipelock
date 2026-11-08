// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWatchHostedEmptyAcknowledgmentSession(t *testing.T) {
	for _, sse := range []bool{false, true} {
		for _, body := range []string{"", `{"jsonrpc":"2.0","id":1,"result":{}}`} {
			t.Run(strings.Join([]string{map[bool]string{false: "JSON", true: "SSE"}[sse], map[bool]string{false: "empty", true: "body"}[body != ""]}, "/"), func(t *testing.T) {
				want := body
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Mcp-Session-Id", "admitted-session")
					w.Header().Set(pipelockSessionTokenHeader, strings.Repeat("a", 43))
					if sse {
						w.Header().Set("Content-Type", "text/event-stream")
					} else {
						w.Header().Set("Content-Type", "application/json")
					}
					w.WriteHeader(http.StatusAccepted)
					if sse && body != "" {
						_, _ = io.WriteString(w, "data: "+body+"\n\n")
					} else {
						_, _ = io.WriteString(w, body)
					}
				}))
				defer server.Close()
				client := NewHTTPClient(server.URL, nil)
				client.WatchOnly = func() bool { return true }
				reader, err := client.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
				if err != nil {
					t.Fatal(err)
				}
				got, err := reader.ReadMessage()
				if body == "" {
					if !errors.Is(err, io.EOF) {
						t.Fatalf("err=%v", err)
					}
				} else if err != nil || string(got) != want {
					t.Fatalf("body=%q err=%v", got, err)
				}
				if client.SessionID() != "admitted-session" || client.listenerSessionToken != strings.Repeat("a", 43) {
					t.Fatalf("session=%q token=%q", client.SessionID(), client.listenerSessionToken)
				}
			})
		}
	}
}
