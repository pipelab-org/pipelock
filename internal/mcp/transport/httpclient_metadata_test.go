// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPClientPerMessageHeaders(t *testing.T) {
	for _, modern := range []bool{false, true} {
		name := "legacy"
		if modern {
			name = "current"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				want := "static"
				if modern {
					want = "tools/call"
				}
				if got := r.Header.Values("Mcp-Method"); len(got) != 1 || got[0] != want {
					t.Errorf("method=%v", got)
				}
				if modern && (r.Header.Get("Mcp-Name") != "echo" || r.Header.Get("Mcp-Param-Value") != "body" || r.Header.Get("Mcp-Param-Other") != "") {
					t.Errorf("routing=%v", r.Header)
				}
				if r.Header.Get("Authorization") != "Bearer fixture" {
					t.Error("lost authorization")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
			}))
			defer server.Close()
			client := NewHTTPClient(server.URL, http.Header{"mcp-method": {"static"}, "MCP-NAME": {"static"}, "mcp-param-value": {"static"}, "Mcp-Param-Other": {"static"}, "Authorization": {"Bearer fixture"}})
			opts := HTTPMessageOptions{}
			if modern {
				opts.Headers = http.Header{"Mcp-Method": {"tools/call"}, "Mcp-Name": {"echo"}, "Mcp-Param-Value": {"body"}}
			}
			reader, err := client.SendMessageWithOptions(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"value":"body"}}}`), opts)
			if err != nil {
				t.Fatal(err)
			}
			drain(t, reader)
		})
	}
}

func TestHTTPClientDiscoveryByteBudget(t *testing.T) {
	const message = `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
	for _, tc := range []struct {
		name, body, content string
		budget              int
		wantErr             bool
	}{
		{"exact JSON", message, "application/json", len(message), false},
		{"over JSON", message + " ", "application/json", len(message), true},
		{"SSE framing charged", ":" + strings.Repeat("x", 80) + "\n\ndata: " + message + "\n\n", "text/event-stream", 80, true},
		{"SSE accepted", "data: " + message + "\n\n", "text/event-stream", len(message) + 8, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.content)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := NewHTTPClient(server.URL, nil)
			budget := tc.budget
			reader, err := client.SendMessageWithOptions(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), HTTPMessageOptions{ResponseByteBudget: &budget})
			if err != nil {
				t.Fatal(err)
			}
			_, err = reader.ReadMessage()
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantErr=%v remaining=%d", err, tc.wantErr, budget)
			}
			if closer, ok := reader.(io.Closer); ok {
				_ = closer.Close()
			}
		})
	}
}

func TestHTTPClientPreserveSession(t *testing.T) {
	const message = `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
	for _, tc := range []struct {
		name, content, body string
		status              int
		validate            bool
	}{
		{"JSON", "application/json", message, http.StatusOK, false},
		{"validated JSON", "application/json", message, http.StatusOK, true},
		{"validated SSE", "text/event-stream", "data: " + message + "\n\n", http.StatusOK, true},
		{"empty acknowledgement", "application/json", "", http.StatusAccepted, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			originalToken := strings.Repeat("a", 43)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Mcp-Session-Id") != "original-session" || r.Header.Get(pipelockSessionTokenHeader) != originalToken {
					t.Error("private request lost established session")
				}
				w.Header().Set("Mcp-Session-Id", "replacement-session")
				w.Header().Set(pipelockSessionTokenHeader, strings.Repeat("b", 43))
				w.Header().Set("Content-Type", tc.content)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := NewHTTPClient(server.URL, nil)
			client.sessionID = "original-session"
			client.listenerSessionToken = originalToken
			if tc.validate {
				client.ResponseKeyValidator = func([]byte) error { return nil }
			}
			reader, err := client.SendMessageWithOptions(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), HTTPMessageOptions{PreserveSession: true})
			if err != nil {
				t.Fatal(err)
			}
			drain(t, reader)
			if client.SessionID() != "original-session" || client.listenerSessionToken != originalToken {
				t.Fatal("private response changed session state")
			}
		})
	}
}
