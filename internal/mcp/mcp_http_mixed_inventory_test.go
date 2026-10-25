// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// One principal's lists record header contracts into one registry. A legacy
// list must not reserve and commit inside a modern list's reservation window,
// or the modern list is delivered last while its contract is discarded as stale
// and contradicting mirrors are forwarded under the legacy definition.
func TestHTTPListener_HeaderContractsMixedVersionOrdering(t *testing.T) {
	for _, tc := range []struct {
		name, legacy string
		// A batched list response is delivered but records no header contract,
		// so it never governs even when delivered last.
		recordsContracts bool
	}{
		{"list", `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`, true},
		{"batch", `[{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paused, resume, legacyArrived := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var resumeOnce, arrivedOnce sync.Once
			unblock := func() { resumeOnce.Do(func() { close(resume) }) }
			defer unblock()
			var counting, armed atomic.Bool
			var modernChecks, pauseAt, calls atomic.Int32
			opts := paramContractOpts(t)
			opts.ServerIdentityHeadersFn = func(headers http.Header) ServerIdentity {
				version := headers.Get("Mcp-Protocol-Version")
				if version == currentMCPVersion && headers.Get("Mcp-Method") == "tools/list" && (counting.Load() || armed.Load()) {
					// The last check of a modern list is the output boundary,
					// after inventory reservation and before its commit.
					if n := modernChecks.Add(1); armed.Load() && n == pauseAt.Load() {
						close(paused)
						<-resume
					}
				}
				if version == "2025-11-25" {
					arrivedOnce.Do(func() { close(legacyArrived) })
				}
				return ServerIdentity{Name: "vendor", PolicyName: "vendor", Binding: "same", BindingMode: "verified-local-session", Revision: "revision"}
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var batch []struct {
					ID     json.RawMessage
					Method string
				}
				var single struct {
					ID     json.RawMessage
					Method string
				}
				w.Header().Set("Content-Type", "application/json")
				// Legacy clients receive the definition without its annotation.
				schema := headerStateSchema
				if r.Header.Get("Mcp-Protocol-Version") != currentMCPVersion {
					schema = `{"type":"object"}`
				}
				decoder := json.NewDecoder(r.Body)
				if r.Header.Get("Mcp-Protocol-Version") != currentMCPVersion && tc.name == "batch" {
					if err := decoder.Decode(&batch); err != nil || len(batch) != 1 {
						t.Errorf("legacy batch: %v", err)
						return
					}
					_, _ = fmt.Fprintf(w, `[{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}]`, batch[0].ID, headerStateDefs(schema, "Echo input"))
					return
				}
				if err := decoder.Decode(&single); err != nil {
					t.Error(err)
					return
				}
				if single.Method == "tools/list" {
					_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":%s,"nextCursor":"next-page","_meta":{"cache":"private"}}}`, single.ID, headerStateDefs(schema, "Echo input"))
					return
				}
				calls.Add(1)
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[]}}`, single.ID)
			}))
			defer upstream.Close()
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			f := &headerStateFixture{url: baseURL}
			counting.Store(true)
			requireHeaderStateList(t, f.list(t), true) // seeds names so capacity cannot mask ordering
			counting.Store(false)
			pauseAt.Store(2 * modernChecks.Load())
			armed.Store(true)

			modernDone := make(chan string, 1)
			go func() { modernDone <- f.list(t) }()
			select {
			case <-paused:
			case <-time.After(testwait.Deadline(5 * time.Second)):
				t.Fatal("modern inventory did not reach its output boundary")
			}
			type reply struct {
				status int
				body   string
			}
			legacyDone := make(chan reply, 1)
			go func() {
				headers := http.Header{"Content-Type": {"application/json"}, "Proxy-Authorization": {headerStateBearer}, "Mcp-Protocol-Version": {"2025-11-25"}}
				status, _, body := postWireContractRequest(t, baseURL, tc.legacy, headers)
				legacyDone <- reply{status, body}
			}()
			select {
			case <-legacyArrived:
			case <-time.After(testwait.Deadline(5 * time.Second)):
				t.Fatal("legacy inventory request did not arrive")
			}
			var legacy reply
			legacyFirst := false
			select {
			case legacy = <-legacyDone:
				legacyFirst = true
			case <-time.After(testwait.Deadline(time.Second)):
			}
			unblock()
			select {
			case body := <-modernDone:
				requireHeaderStateList(t, body, true)
			case <-time.After(testwait.Deadline(5 * time.Second)):
				t.Fatal("modern inventory did not finish")
			}
			if !legacyFirst {
				select {
				case legacy = <-legacyDone:
				case <-time.After(testwait.Deadline(5 * time.Second)):
					t.Fatal("legacy inventory did not finish")
				}
			}
			if legacy.status != http.StatusOK {
				t.Fatalf("legacy status=%d body=%s", legacy.status, legacy.body)
			}
			headers := currentWireHeaders(methodToolsCall, "echo")
			headers.Set("Proxy-Authorization", headerStateBearer)
			headers.Set("Mcp-Param-Region", "us")
			status, _, body := postWireContractRequest(t, baseURL, currentWireBody(4, methodToolsCall, `"name":"echo","arguments":{"region":"eu"}`), headers)
			if !legacyFirst && tc.recordsContracts {
				// The legacy list was delivered last; its definition governs.
				if status != http.StatusOK || calls.Load() != 1 {
					t.Fatalf("latest delivered legacy contract lost: status=%d upstream=%d body=%s", status, calls.Load(), body)
				}
				return
			}
			// The modern list was delivered last, so its binding governs.
			if status != http.StatusBadRequest || calls.Load() != 0 {
				t.Fatalf("modern binding delivered last was lost (legacy first=%v): status=%d upstream=%d body=%s", legacyFirst, status, calls.Load(), body)
			}
			requireWireHeaderMismatch(t, status, body)
		})
	}
}
