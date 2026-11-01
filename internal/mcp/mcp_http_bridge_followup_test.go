// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestMCPRoutedMethodContract(t *testing.T) {
	for _, tc := range []struct{ method, field string }{
		{methodToolsCall, "name"}, {methodResourcesRead, "uri"}, {methodPromptsGet, "name"}, {"ping", ""},
	} {
		t.Run(tc.method, func(t *testing.T) {
			if got := routingFieldForMethod(tc.method); got != tc.field {
				t.Errorf("routing field = %q, want %q", got, tc.field)
			}
			body := []byte(currentWireBody(1, tc.method, `"name":"echo","uri":"docs://notes","arguments":{}`))
			frame := ParseMCPFrame(body)
			baseline := tools.NewToolBaseline()
			if err := baseline.SetToolHeaderBindings([]tools.ToolDef{{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}}); err != nil {
				t.Fatal(err)
			}
			headers, err := synthesizeMCPRequestHeaders(frame, baseline)
			if err != nil {
				t.Fatal(err)
			}
			if (headers.Get(listenerMCPName) != "") != (tc.field != "") {
				t.Fatalf("routing headers = %v", headers)
			}
			headers.Set(listenerProtocolVersion, currentMCPVersion)
			if !currentProtocolHeadersMatchFrame(headers, frame) {
				t.Fatal("listener refused synthesized routing headers")
			}
			headers.Del(listenerMCPName)
			if currentProtocolHeadersMatchFrame(headers, frame) != (tc.field == "") {
				t.Fatal("listener routing requirement differs from synthesis")
			}
			state := &mcpBridgeHeaders{client: transport.NewHTTPClient("https://api.vendor.example/mcp", nil), state: &mcpListenerClientState{baseline: baseline}}
			notification := bytes.Replace(body, []byte(`"id":1,`), nil, 1)
			_, err = state.prepare(t.Context(), notification)
			if (err != nil) != (tc.field != "") {
				t.Fatalf("notification refusal = %v", err)
			}
		})
	}
}

// Return one message per Read, cancelling immediately before the next message
// reaches the loop. Close is intentionally inert so the check is deterministic.
type bridgeCancelReader struct {
	lines   []string
	cancel  context.CancelFunc
	readErr error
}

func (r *bridgeCancelReader) Read(p []byte) (int, error) {
	if len(r.lines) == 0 {
		return 0, io.EOF
	}
	if len(r.lines) == 1 {
		if r.readErr != nil {
			return 0, r.readErr
		}
		r.cancel()
	}
	line := r.lines[0]
	r.lines = r.lines[1:]
	return copy(p, line+"\n"), nil
}
func (*bridgeCancelReader) Close() error { return nil }

func TestHTTPBridgeMessageCancelClosesPendingIntent(t *testing.T) {
	testHTTPBridgeInputCleanup(t, nil)
}

func TestHTTPBridgeInputErrorClosesPendingIntent(t *testing.T) {
	testHTTPBridgeInputCleanup(t, io.ErrUnexpectedEOF)
}

func testHTTPBridgeInputCleanup(t *testing.T, readErr error) {
	t.Helper()
	opts := bridgeHeaderOpts(t)
	h := openReceiptHarness(t, &opts, true)
	var deletes, calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		frame := ParseMCPFrame(body)
		if frame.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", "pending-session")
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18"}}`, frame.ID)
			return
		}
		calls.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer up.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	in := &bridgeCancelReader{cancel: cancel, readErr: readErr, lines: []string{
		`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
	}}
	var out, logs bytes.Buffer
	wantErr := readErr
	if wantErr == nil {
		wantErr = context.Canceled
	}
	if err := RunHTTPProxy(ctx, in, &out, &logs, up.URL, nil, opts); !errors.Is(err, wantErr) {
		t.Fatalf("bridge error = %v", err)
	}
	if calls.Load() != 1 || deletes.Load() != 1 {
		t.Errorf("calls=%d deletes=%d, want 1 each", calls.Load(), deletes.Load())
	}
	assertBridgeIntentsPaired(t, h.dir)
}

func assertBridgeIntentsPaired(t *testing.T, dir string) {
	t.Helper()
	intents := map[string]bool{}
	outcomes := map[string]int{}
	for _, r := range readActionReceipts(t, dir) {
		a := r.ActionRecord
		if a.DecisionPhase == receipt.DecisionPhaseIntent {
			intents[a.ActionID] = true
		}
		if a.DecisionPhase == receipt.DecisionPhaseOutcome {
			outcomes[a.ActionID]++
		}
	}
	if len(intents) == 0 {
		t.Fatal("no intent positive control")
	}
	for id := range intents {
		if outcomes[id] != 1 {
			t.Errorf("intent %s has %d outcomes, want 1", id, outcomes[id])
		}
	}
	// A held call writes defer and resolution receipts, never an intent, so a
	// terminal outcome emitted under its tracker entry would be an orphan.
	for id := range outcomes {
		if !intents[id] {
			t.Errorf("outcome %s has no matching intent", id)
		}
	}
}

func TestHTTPBridgeLegacyReinitializeSessionHeader(t *testing.T) {
	var inits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		frame := ParseMCPFrame(body)
		if frame.Method == "initialize" {
			if got := r.Header.Get("Mcp-Session-Id"); got != "" {
				t.Errorf("initialize carried old session %q", got)
			}
			if inits.Add(1) == 1 {
				w.Header().Set("Mcp-Session-Id", "old-session")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18"}}`, frame.ID)
			return
		}
		if got := r.Header.Get("Mcp-Session-Id"); got != "" {
			t.Errorf("new session retained old session %q", got)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer up.Close()
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`, "",
	}, "\n")
	var out, logs bytes.Buffer
	if err := RunHTTPProxy(t.Context(), strings.NewReader(input), &out, &logs, up.URL, nil, bridgeHeaderOpts(t)); err != nil {
		t.Fatal(err)
	}
	if inits.Load() != 2 {
		t.Fatalf("initialize calls=%d", inits.Load())
	}
}

func bridgeFollowupDeferOpts(t *testing.T) (MCPProxyOpts, *deferred.Manager) {
	t.Helper()
	opts := bridgeHeaderOpts(t)
	manager := newDeferKillManager(t)
	opts.DeferManager = manager
	policy := deferApprovalPolicy(config.DeferResolverProfile{})
	policy.Rules[0].ToolPattern = regexp.MustCompile(`^echo$`)
	policy.Rules[0].ResolutionPolicy.ResolverProfile = ""
	opts.PolicyCfg = policy
	return opts, manager
}

func TestHTTPBridgeDiscoveryKillSwitch(t *testing.T) {
	for _, src := range killSources() {
		for _, stalled := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/stalled=%t", src.name, stalled), func(t *testing.T) {
				fastKillPoll(t)
				opts, manager := bridgeFollowupDeferOpts(t)
				ks, arm := src.ctl(t)
				opts.KillSwitch = ks
				h := openReceiptHarness(t, &opts, true)
				entered := make(chan struct{})
				cancelled := make(chan struct{})
				release := make(chan struct{})
				var calls atomic.Int32
				up := bridgeHeaderUpstream(t, func(w http.ResponseWriter, r *http.Request, _ MCPFrame) {
					close(entered)
					select {
					case <-r.Context().Done():
					case <-release:
						w.WriteHeader(http.StatusInternalServerError)
					}
					close(cancelled)
				}, func(w http.ResponseWriter, _ *http.Request, _ MCPFrame) {
					calls.Add(1)
					w.WriteHeader(http.StatusAccepted)
				})
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				inR, inW := io.Pipe()
				defer func() { _ = inR.Close(); _ = inW.Close() }()
				var out, logs syncBuffer
				done := make(chan error, 1)
				go func() { done <- RunHTTPProxy(ctx, inR, &out, &logs, up.URL, nil, opts) }()
				defer func() {
					cancel()
					_ = inW.Close()
					select {
					case err := <-done:
						if err != nil && !errors.Is(err, context.Canceled) {
							t.Errorf("bridge cleanup: %v", err)
						}
					case <-time.After(testwait.Deadline(5 * time.Second)):
						t.Error("bridge did not stop")
					}
				}()
				if _, err := io.WriteString(inW, bridgeHeaderCall(`{"region":"body"}`)+"\n"); err != nil {
					t.Fatal(err)
				}
				testwait.For(t, 5*time.Second, func() bool { return manager.HeldCount() == 1 }, "held call")
				held := manager.Snapshot()[0]
				resolved := make(chan error, 1)
				go func() { resolved <- manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceApproval) }()
				select {
				case <-entered:
				case <-time.After(testwait.Deadline(5 * time.Second)):
					t.Fatal("discovery not entered")
				}
				arm()
				if !stalled {
					close(release)
				}
				select {
				case <-cancelled:
				case <-time.After(testwait.Deadline(3 * time.Second)):
					// Unblock the old implementation before failing, so the reproduction
					// never leaves a 120-second request or a resolving goroutine behind.
					cancel()
					if err := <-resolved; err != nil {
						t.Errorf("cancelled resolution: %v", err)
					}
					t.Fatalf("discovery did not observe kill switch; out=%s logs=%s", out.String(), logs.String())
				}
				select {
				case err := <-resolved:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(testwait.Deadline(5 * time.Second)):
					t.Fatal("resolution did not finish")
				}
				if calls.Load() != 0 || !strings.Contains(out.String(), `"code":-32004`) || strings.Contains(out.String(), `"code":-32020`) {
					t.Errorf("calls=%d out=%s logs=%s", calls.Load(), out.String(), logs.String())
				}
				assertTerminalJournal(t, manager, held.DeferID, deferred.StateResolvedBlock, deferred.SourceKillSwitch)
				resolutions := 0
				for _, r := range readActionReceipts(t, h.dir) {
					a := r.ActionRecord
					if a.DecisionPhase == receipt.DecisionPhaseResolution && a.DeferID == held.DeferID {
						resolutions++
						if a.Verdict != config.ActionBlock || a.ResolutionSource != deferred.SourceKillSwitch {
							t.Errorf("resolution = %+v", a)
						}
					}
				}
				if resolutions != 1 {
					t.Errorf("resolution receipts = %d, want 1", resolutions)
				}
			})
		}
	}
}

func TestHTTPBridgeDeferredFailureClosesTracking(t *testing.T) {
	for _, failure := range []string{"send", "scan", "scan_after_reply"} {
		t.Run(failure, func(t *testing.T) {
			opts, manager := bridgeFollowupDeferOpts(t)
			h := openReceiptHarness(t, &opts, true)
			up := bridgeHeaderUpstream(t, func(w http.ResponseWriter, _ *http.Request, f MCPFrame) {
				discoveryList(w, f, headerStateDefs(bridgeHeaderSchema, "Echo input"), "")
			}, func(w http.ResponseWriter, _ *http.Request, f MCPFrame) {
				if f.ToolCallName == "echo" {
					if failure == "scan_after_reply" {
						body := fmt.Sprintf("data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[]}}\n\n", f.ID)
						w.Header().Set("Content-Type", "text/event-stream")
						w.Header().Set("Content-Length", fmt.Sprint(len(body)+1))
						_, _ = io.WriteString(w, body)
						return
					}
					if failure == "send" {
						w.WriteHeader(http.StatusInternalServerError)
					} else {
						w.Header().Set("Content-Length", "2")
						_, _ = io.WriteString(w, `{`)
					}
					return
				}
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[]}}`, f.ID)
			})
			inR, inW := io.Pipe()
			defer func() { _ = inR.Close(); _ = inW.Close() }()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var out, logs syncBuffer
			done := make(chan error, 1)
			go func() { done <- RunHTTPProxy(ctx, inR, &out, &logs, up.URL, nil, opts) }()
			defer func() {
				cancel()
				_ = inW.Close()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, context.Canceled) {
						t.Errorf("bridge cleanup: %v", err)
					}
				case <-time.After(testwait.Deadline(5 * time.Second)):
					t.Error("bridge did not stop")
				}
			}()
			// Legacy negotiation avoids unrelated discovery for the follow-up call.
			call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
			if _, err := io.WriteString(inW, call+"\n"); err != nil {
				t.Fatal(err)
			}
			testwait.For(t, 5*time.Second, func() bool { return manager.HeldCount() == 1 }, "held call")
			held := manager.Snapshot()[0]
			if err := manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceApproval); err != nil {
				t.Fatal(err)
			}
			if failure == "scan_after_reply" {
				if strings.Count(out.String(), `"id":2`) != 1 || strings.Contains(out.String(), `"error"`) {
					t.Errorf("answered request received a duplicate error: out=%s logs=%s", out.String(), logs.String())
				}
			} else if !strings.Contains(out.String(), `"id":2,"error"`) {
				t.Errorf("failure did not return an error at release time: out=%s logs=%s", out.String(), logs.String())
			}
			// A finished call no longer owns its RPC ID. Its stale empty tracker entry
			// must not swallow the next call's intent/outcome metadata.
			next := strings.Replace(call, `"name":"echo"`, `"name":"other"`, 1)
			if _, err := io.WriteString(inW, next+"\n"); err != nil {
				t.Fatal(err)
			}
			testwait.For(t, 5*time.Second, func() bool { return strings.Contains(out.String(), `"result":{"content":[]}`) }, "next call response")
			// The unbuffered pipe accepts this blank line only when the bridge
			// reads again, after the previous response and outcome finish.
			if _, err := io.WriteString(inW, "\n"); err != nil {
				t.Fatal(err)
			}
			assertBridgeIntentsPaired(t, h.dir)
		})
	}
}
