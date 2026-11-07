// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestWatchHTTPStreamSpoolCleanup(t *testing.T) {
	for _, tc := range []struct {
		name               string
		secret, incomplete bool
	}{
		{name: "forward"}, {name: "credential", secret: true}, {name: "read failure", incomplete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("TMPDIR", dir)
			var calls atomic.Int32
			received := make(chan string, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				data, _ := io.ReadAll(r.Body)
				received <- string(data)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
			}))
			defer upstream.Close()
			first := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"value":"`)
			last := []byte(`ordinary"}}` + "\n")
			if tc.secret {
				last = []byte(fakeAWSKey() + `"}}` + "\n")
			}
			reader := &watchChunkReader{chunks: [][]byte{last}}
			if tc.incomplete {
				reader.chunks = nil
			}
			opts := testOpts(testInputScanner(t))
			opts.WatchOnly = true
			client := transport.NewHTTPClient(upstream.URL, nil)
			client.WatchOnly = opts.watchOnly
			var output bytes.Buffer
			err := forwardWatchHTTPInput(t.Context(), first, &transport.UninspectedMessageChunkError{}, reader, client, transport.NewStdioWriter(&output), io.Discard, opts)
			if tc.secret || tc.incomplete {
				if err == nil || calls.Load() != 0 {
					t.Fatalf("refused request escaped: calls=%d err=%v", calls.Load(), err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				got := <-received
				if got != string(first)+string(last) || !strings.Contains(output.String(), `"result":{}`) {
					t.Fatalf("stream changed: body=%q response=%q", got, output.String())
				}
			}
			files, readErr := os.ReadDir(dir)
			if readErr != nil || len(files) != 0 {
				t.Fatalf("spool retained: files=%v err=%v", files, readErr)
			}
		})
	}
}
