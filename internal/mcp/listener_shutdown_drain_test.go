// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/httpstream"
)

func TestRunHTTPListenerProxy_DrainResult(t *testing.T) {
	for _, incomplete := range []bool{true, false} {
		name := "clean"
		if incomplete {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				close(entered)
				<-release
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
			}))
			t.Cleanup(upstream.Close)
			t.Cleanup(unblock)
			ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			timeout := 5 * time.Second
			if incomplete {
				timeout = 25 * time.Millisecond
			}
			sc := testScannerForHTTP(t)
			done := make(chan error, 1)
			go func() {
				done <- RunHTTPListenerProxy(ctx, ln, upstream.URL, io.Discard, MCPProxyOpts{
					Scanner: sc, ListenerShutdownTimeout: timeout,
				})
			}()
			requestDone := make(chan struct{})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+ln.Addr().String()+"/", strings.NewReader(jsonToolsList))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			go func() {
				defer close(requestDone)
				// The test deadline bounds this wait; a client timeout must not
				// masquerade as the proxy force-closing the connection.
				client := &http.Client{}
				resp, requestErr := client.Do(req)
				if requestErr == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
			}()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("request did not reach upstream")
			}
			cancel()
			if !incomplete {
				unblock()
			}
			select {
			case err := <-done:
				if incomplete {
					if !errors.Is(err, httpstream.ErrShutdownIncomplete) || !errors.Is(err, context.DeadlineExceeded) {
						t.Errorf("RunHTTPListenerProxy = %v, want ErrShutdownIncomplete and DeadlineExceeded", err)
					}
					if err == nil || !strings.Contains(err.Error(), "MCP HTTP listener") {
						t.Errorf("RunHTTPListenerProxy = %v, want listener name", err)
					}
				} else if err != nil {
					t.Errorf("clean drain = %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("listener did not stop")
			}
			// Before releasing the upstream, the force-close must unblock the client.
			select {
			case <-requestDone:
			case <-time.After(10 * time.Second):
				t.Fatal("downstream request was not closed")
			}
		})
	}
}
