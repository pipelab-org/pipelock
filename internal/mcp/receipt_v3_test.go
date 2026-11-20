// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type v3TestPeer func([]byte) error

func (f v3TestPeer) WriteMessage(msg []byte) error { return f(msg) }

func TestMCPV3ConfirmsUpstreamSend(t *testing.T) {
	for _, surface := range []string{"stdio", "bridge", "listener", "listener-sse", "listener-delete"} {
		t.Run(surface, func(t *testing.T) {
			for _, live := range []bool{true, false} {
				name := "closed"
				if live {
					name = "live"
				}
				t.Run(name, func(t *testing.T) {
					exerciseMCPV3Upstream(t, surface, live)
				})
			}
		})
	}
}

func exerciseMCPV3Upstream(t *testing.T, surface string, live bool) {
	t.Helper()
	receiptSurface := surface
	if surface == "listener-delete" || surface == "listener-sse" {
		receiptSurface = "listener"
	}
	dir, writer, verify := newMCPV3Stream(t, receiptSurface)
	if !live {
		if err := writer.Close(t.Context(), nil); err != nil {
			t.Fatal(err)
		}
	}
	var hits atomic.Int32
	atEntry := make(chan error, 2)
	observe := func(ctx context.Context) {
		hits.Add(1)
		result, err := v3.VerifyPaths(ctx, []string{dir}, verify)
		if err == nil && !hasMCPV3State(result, "outcome_unknown") {
			err = errors.New("the sender reached the peer before its signed intent")
		}
		atEntry <- err
	}
	opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), Transport: transportMCPStdio, RequireReceipts: true, ReceiptV3: writer}
	switch surface {
	case "stdio":
		blocked := make(chan BlockedRequest, 1)
		ForwardScannedInput(
			transport.NewStdioReader(strings.NewReader(cleanToolsCallRequest+"\n")),
			v3TestPeer(func([]byte) error { observe(t.Context()); return nil }),
			io.Discard, config.ActionWarn, config.ActionBlock, blocked, nil, NewRequestTracker(), opts,
		)
		if refusal, denied := <-blocked; denied == live {
			t.Fatalf("unexpected stdio denial state: denied=%t, refusal=%+v", denied, refusal)
		}
	default:
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if surface == "listener-delete" && r.Method == http.MethodDelete {
				observe(r.Context())
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if !isMCPUpstreamRequest(r) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			observe(r.Context())
			if surface == "listener-sse" {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "event: message\ndata: "+cleanToolsCallResponse+"\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, cleanToolsCallResponse)
		}))
		t.Cleanup(upstream.Close)
		if surface == "bridge" {
			opts.Transport = "mcp_http"
			var out strings.Builder
			if err := RunHTTPProxy(t.Context(), strings.NewReader(cleanToolsCallRequest+"\n"), &out, io.Discard, upstream.URL, nil, opts); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "result") != live {
				t.Fatalf("unexpected bridge reply %q", out.String())
			}
		} else {
			opts.Transport = "mcp_http_listener"
			url, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			if surface == "listener-delete" {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, url, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				if err := resp.Body.Close(); err != nil {
					t.Fatal(err)
				}
				want := http.StatusForbidden
				if live {
					want = http.StatusNoContent
				}
				if resp.StatusCode != want {
					t.Fatalf("DELETE status %d, want %d", resp.StatusCode, want)
				}
			} else {
				status, body := postToolsCall(t, url)
				if strings.Contains(body, "result") != live {
					t.Fatalf("unexpected listener reply %d %s", status, body)
				}
			}
		}
	}

	if !live {
		if hits.Load() != 0 {
			t.Fatalf("unconfirmed receipt released %d sends", hits.Load())
		}
		return
	}
	if hits.Load() != 1 {
		t.Fatalf("peer received %d sends, want exactly one", hits.Load())
	}
	select {
	case err := <-atEntry:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("peer did not inspect the intent")
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result, err := v3.VerifyPaths(t.Context(), []string{dir}, verify)
	wantCompleted := int64(1)
	if surface == "bridge" || surface == "listener" || surface == "listener-sse" {
		wantCompleted = 2
	}
	if err != nil || result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil ||
		*result.Counts.EffectsCompleted != wantCompleted {
		t.Fatalf("expected %d completed effects: %+v (%v)", wantCompleted, result, err)
	}
}

func hasMCPV3State(result v3.Result, want string) bool {
	if result.Integrity == "failed" || result.Counts.Decisions == nil {
		return false
	}
	for _, state := range *result.Counts.Decisions {
		if state.State == want && state.Count == 1 {
			return true
		}
	}
	return false
}

func newMCPV3Stream(t *testing.T, surface string) (string, *v3.StreamWriter, v3.Options) {
	t.Helper()
	dir := t.TempDir()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	writer, err := v3.OpenStreamWriter(t.Context(), v3.StreamWriterOptions{
		Dir: dir, SigningKey: key, PolicyHash: v3.Digest(nil),
		Identity: v3.Writer{Instance: "example", Product: "Pipelock", Version: "3"},
		Coverage: v3.Coverage{
			ReceiptsRequired: true, Surfaces: []string{surface},
			RedactionRuleset: v3.Ruleset{ID: "example", Version: "1", Hash: v3.Digest(nil)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close(context.Background(), nil) })
	return dir, writer, v3.Options{Keys: []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}, Directory: true, AllowPrefix: true}
}

func TestMCPV3ConfirmsDirectResponseDelivery(t *testing.T) {
	for _, live := range []bool{true, false} {
		name := "closed"
		if live {
			name = "live"
		}
		t.Run(name, func(t *testing.T) {
			dir, writer, verify := newMCPV3Stream(t, transportMCPStdio)
			if !live {
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
			}
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), Transport: transportMCPStdio,
				RequireReceipts: true, ReceiptV3: writer, v3DirectResponseDelivery: true,
			}
			hits := 0
			peer := v3TestPeer(func(msg []byte) error {
				hits++
				if string(msg) != cleanToolsCallResponse {
					t.Errorf("client received %q", msg)
				}
				result, err := v3.VerifyPaths(t.Context(), []string{dir}, verify)
				if err != nil || !hasMCPV3State(result, "outcome_unknown") {
					t.Errorf("client write reached before a verified delivery intent: %+v (%v)", result, err)
				}
				return nil
			})
			if _, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(cleanToolsCallResponse)), peer,
				io.Discard, NewRequestTracker(), opts); (err == nil) != live {
				t.Fatalf("response writer error %v (writer live=%t)", err, live)
			}
			if !live {
				if hits != 0 {
					t.Fatalf("client saw %d writes after recorder closure", hits)
				}
				return
			}
			if hits != 1 {
				t.Fatalf("client saw %d writes, want one", hits)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, verify)
			if err != nil || result.Verdict != "VALID" || !hasMCPV3State(result, "completed") {
				t.Fatalf("delivery outcome missing: %+v (%v)", result, err)
			}
		})
	}
}

func TestMCPV3ListenerRefusesUnconfirmedResponse(t *testing.T) {
	for _, wire := range []string{"json", "sse"} {
		t.Run(wire, func(t *testing.T) {
			_, writer, _ := newMCPV3Stream(t, "listener")
			received := make(chan error, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !isMCPUpstreamRequest(r) {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				received <- writer.Close(r.Context(), nil)
				if wire == "sse" {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "event: message\ndata: "+cleanToolsCallResponse+"\n\n")
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, cleanToolsCallResponse)
			}))
			t.Cleanup(upstream.Close)
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), Transport: "mcp_http_listener",
				RequireReceipts: true, ReceiptV3: writer,
			}
			url, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			status, body := postToolsCall(t, url)
			if status != http.StatusBadGateway || strings.Contains(body, "result") {
				t.Fatalf("listener delivered an unconfirmed response: %d %s", status, body)
			}
			select {
			case err := <-received:
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("listener did not reach the upstream endpoint")
			}
		})
	}
}

func TestMCPV3RedirectDispatchOutcome(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("redirect executable requires a Unix shell")
	}
	for _, surface := range []string{transportMCPStdio, transportMCPHTTP} {
		for _, tc := range []struct {
			name, outcome string
			wantStarted   bool
		}{
			{name: "completed", outcome: "completed", wantStarted: true},
			{name: "handler failure", outcome: "attempt_unknown", wantStarted: true},
			{name: "missing executable", outcome: "not_released"},
			{name: "closed writer"},
		} {
			t.Run(surface+"/"+tc.name, func(t *testing.T) {
				dir, writer, verify := newMCPV3Stream(t, surface)
				marker := filepath.Join(t.TempDir(), "executed")
				command := "printf executed > \"$1\"; printf 'ordinary reply'"
				if tc.name == "handler failure" {
					command += "; exit 7"
				}
				handler := []string{"/bin/sh", "-c", command, "handler", marker}
				if tc.name == "missing executable" {
					handler = []string{filepath.Join(t.TempDir(), "missing")}
				}
				if tc.name == "closed writer" {
					if err := writer.Close(t.Context(), nil); err != nil {
						t.Fatal(err)
					}
				}
				opts := MCPProxyOpts{
					Scanner: testInputScanner(t), Transport: surface, RequireReceipts: true, ReceiptV3: writer,
					PolicyCfg: policy.New(config.MCPToolPolicy{
						Enabled: true, Action: config.ActionWarn,
						RedirectProfiles: map[string]config.RedirectProfile{"audited": {Exec: handler, Reason: "audited operation"}},
						Rules: []config.ToolPolicyRule{{
							Name: "redirect", ToolPattern: "^echo$", Action: config.ActionRedirect, RedirectProfile: "audited",
						}},
					}),
				}
				if surface == transportMCPStdio {
					blocked := make(chan BlockedRequest, 2)
					ForwardScannedInput(transport.NewStdioReader(strings.NewReader(cleanToolsCallRequest)),
						v3TestPeer(func([]byte) error {
							t.Error("redirect forwarded the original request")
							return nil
						}), io.Discard, config.ActionBlock, config.ActionBlock, blocked, nil, nil, opts)
				} else {
					scanHTTPInputDecision([]byte(cleanToolsCallRequest), io.Discard, "session", "session", opts)
				}
				_, statErr := os.Stat(marker)
				if got := statErr == nil; got != tc.wantStarted {
					t.Fatalf("redirect started=%t, want %t (%v)", got, tc.wantStarted, statErr)
				}
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				result, err := v3.VerifyPaths(t.Context(), []string{dir}, verify)
				if err != nil || result.Verdict != "VALID" {
					t.Fatalf("redirect evidence failed verification: %+v (%v)", result, err)
				}
				if tc.outcome != "" {
					assertMCPV3RedirectOutcome(t, dir, tc.outcome)
				}
			})
		}
	}
}

func assertMCPV3RedirectOutcome(t *testing.T, dir, outcome string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.receipt-v3.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("want one receipt file, got %v (%v)", paths, err)
	}
	data, err := os.ReadFile(filepath.Clean(paths[0]))
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range strings.Split(string(data), "\n") {
		if strings.Contains(record, `"effect_boundary":"redirect_dispatch"`) && strings.Contains(record, `"outcome_class":"`+outcome+`"`) {
			return
		}
	}
	t.Fatalf("no redirect dispatch outcome %q", outcome)
}

func TestMCPV3DeferredSendUsesHoldAndIntent(t *testing.T) {
	for _, surface := range []string{deferred.SurfaceMCPStdio, deferred.SurfaceMCPHTTPUpstream} {
		t.Run(surface, func(t *testing.T) {
			dir, writer, verify := newMCPV3Stream(t, surface)
			manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Minute})
			policy := deferApprovalPolicy(config.DeferResolverProfile{})
			policy.Rules[0].ResolutionPolicy.ResolverProfile = ""
			opts := MCPProxyOpts{
				Scanner: testInputScanner(t), PolicyCfg: policy, DeferManager: manager,
				ReceiptV3: writer, RequireReceipts: true, Transport: surface,
			}
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			input, send := io.Pipe()
			t.Cleanup(func() { _ = send.Close() })
			done, reached := make(chan error, 1), make(chan error, 1)
			checkRelease := func(ctx context.Context) {
				result, err := v3.VerifyPaths(ctx, []string{dir}, verify)
				if err == nil && (!hasMCPV3State(result, "outcome_unknown") || hasMCPV3State(result, "pending")) {
					err = errors.New("held request reached upstream without a release intent")
				}
				reached <- err
			}
			if surface == deferred.SurfaceMCPStdio {
				go func() {
					ForwardScannedInput(
						transport.NewStdioReader(input),
						v3TestPeer(func([]byte) error { checkRelease(ctx); return nil }),
						io.Discard, config.ActionWarn, config.ActionBlock, make(chan BlockedRequest, 4), nil, NewRequestTracker(), opts,
					)
					done <- nil
				}()
			} else {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !isMCPUpstreamRequest(r) {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					checkRelease(r.Context())
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, cleanToolsCallResponse)
				}))
				t.Cleanup(upstream.Close)
				go func() { done <- RunHTTPProxy(ctx, input, io.Discard, io.Discard, upstream.URL, nil, opts) }()
			}
			if _, err := io.WriteString(send, deferKillTestCall); err != nil {
				t.Fatal(err)
			}
			testwait.For(t, 5*time.Second, func() bool { return manager.HeldCount() == 1 }, "signed deferred hold")
			result, err := v3.VerifyPaths(ctx, []string{dir}, verify)
			if err != nil || !hasMCPV3State(result, "pending") {
				t.Fatalf("manager exposed a hold without its signed record: %+v (%v)", result, err)
			}
			select {
			case err := <-reached:
				t.Fatalf("hold forwarded before approval: %v", err)
			default:
			}
			held := manager.Snapshot()[0]
			if decision, err := manager.ResolveApprovalResult(held.DeferID, config.ActionAllow, deferred.SourceOperator); err != nil || decision != config.ActionAllow {
				t.Fatalf("resolve held request: %s (%v)", decision, err)
			}
			select {
			case err := <-reached:
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("approved request did not reach upstream")
			}
			if err := send.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(ctx, nil); err != nil {
				t.Fatal(err)
			}
			result, err = v3.VerifyPaths(ctx, []string{dir}, verify)
			wantCompleted := int64(1)
			if surface == deferred.SurfaceMCPHTTPUpstream {
				wantCompleted = 2
			}
			if err != nil || result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil ||
				*result.Counts.EffectsCompleted != wantCompleted {
				t.Fatalf("held call did not settle: %+v (%v)", result, err)
			}
		})
	}
}

func TestMCPV3ConfirmsGETSubscriptionBeforeContact(t *testing.T) {
	for _, stage := range []string{"healthy", "closed"} {
		t.Run(stage, func(t *testing.T) {
			dir, writer, verifyOpts := newMCPV3Stream(t, deferred.SurfaceMCPHTTPUpstream)
			if stage == "closed" {
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
			}
			var contacts atomic.Int32
			var confirmed atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				contacts.Add(1)
				result, err := v3.VerifyPaths(req.Context(), []string{dir}, verifyOpts)
				confirmed.Store(err == nil && result.Counts.EffectsUnknown != nil && *result.Counts.EffectsUnknown == 1)
				w.WriteHeader(http.StatusMethodNotAllowed)
			}))
			t.Cleanup(srv.Close)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			opts := MCPProxyOpts{
				ReceiptV3: writer, RequireReceipts: true,
				Transport: deferred.SurfaceMCPHTTPUpstream, AuthorityDestination: srv.URL,
			}
			var wg sync.WaitGroup
			startGETStream(ctx, transport.NewHTTPClient(srv.URL, nil), &syncWriter{w: io.Discard},
				&syncWriter{w: io.Discard}, opts, NewRequestTracker(), &wg)
			wg.Wait()
			if stage == "closed" {
				if contacts.Load() != 0 {
					t.Fatal("upstream received a subscription with no confirmed receipt")
				}
				return
			}
			if contacts.Load() != 1 || !confirmed.Load() {
				t.Fatalf("subscription contact lacked prior intent: contacts=%d confirmed=%v", contacts.Load(), confirmed.Load())
			}
		})
	}
}

func TestMCPV3ConfirmsWebSocketBeforeHandshake(t *testing.T) {
	for _, stage := range []string{"healthy", "closed"} {
		t.Run(stage, func(t *testing.T) {
			dir, writer, verifyOpts := newMCPV3Stream(t, deferred.SurfaceMCPWS)
			if stage == "closed" {
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
			}
			var contacts atomic.Int32
			var confirmed atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				contacts.Add(1)
				result, err := v3.VerifyPaths(req.Context(), []string{dir}, verifyOpts)
				confirmed.Store(err == nil && result.Counts.EffectsUnknown != nil && *result.Counts.EffectsUnknown == 1)
				w.WriteHeader(http.StatusMethodNotAllowed)
			}))
			t.Cleanup(srv.Close)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			opts := MCPProxyOpts{ReceiptV3: writer, RequireReceipts: true}
			err := RunWSProxy(ctx, strings.NewReader(""), io.Discard, io.Discard,
				"ws"+strings.TrimPrefix(srv.URL, "http"), opts)
			if stage == "closed" {
				if contacts.Load() != 0 || !errors.Is(err, ErrReceiptRequired) {
					t.Fatalf("upstream received an unconfirmed handshake: contacts=%d error=%v", contacts.Load(), err)
				}
				return
			}
			if contacts.Load() != 1 || !confirmed.Load() || err == nil {
				t.Fatalf("handshake lacked an earlier intent: contacts=%d confirmed=%v error=%v", contacts.Load(), confirmed.Load(), err)
			}
		})
	}
}

func TestMCPV3GeneratedReplyAndRefusal(t *testing.T) {
	dir, writer, verify := newMCPV3Stream(t, "bridge")
	opts := MCPProxyOpts{
		Scanner: testScannerForHTTP(t), Transport: transportMCPStdio,
		RequireReceipts: true, ReceiptV3: writer,
	}
	intent := receipt.EmitOpts{ActionID: receipt.NewActionID(), Transport: opts.Transport, Method: http.MethodPost, Target: "https://upstream.vendor.example"}
	outcome := TrackedRequestOutcome{Receipt: intent}
	emitContractRefusedOutcome(io.Discard, outcome, mcpContractGateOutput{}, mcpContractDeniedReason, 0, opts)
	emitBridgeHeaderContractRefusal(io.Discard, outcome, "header_contract", opts)
	calls := 0
	client := v3TestPeer(func([]byte) error {
		calls++
		result, err := v3.VerifyPaths(t.Context(), []string{dir}, verify)
		if err != nil {
			return err
		}
		if !hasMCPV3State(result, "outcome_unknown") {
			return errors.New("client write reached before the delivery intent")
		}
		return nil
	})
	reply := timeoutErrorResponse([]byte("1"))
	if err := opts.writeMCPGeneratedResponse(io.Discard, client, intent, reply, "response_timeout"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if err := opts.writeMCPGeneratedResponse(io.Discard, client, intent, reply, "response_timeout"); err == nil {
		t.Fatal("generated reply passed a closed receipt writer")
	}
	if calls != 1 {
		t.Fatalf("client saw %d writes, want one", calls)
	}
	result, err := v3.VerifyPaths(t.Context(), []string{dir}, verify)
	if err != nil || result.Verdict != "VALID" || result.Counts.Decisions == nil ||
		!slices.Contains(*result.Counts.Decisions, v3.StateCount{State: "blocked", Count: 2}) || !hasMCPV3State(result, "completed") {
		t.Fatalf("refusal or reply absent: %+v (%v)", result, err)
	}
}

func TestMCPV3ListenerCallerIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, doorMode, token string
		status                int
		verified              bool
	}{
		{"jwt", config.MCPDoorJWT, "a", http.StatusOK, true},
		{"introspection", config.MCPDoorIntrospection, "a", http.StatusOK, true},
		{"failed", config.MCPDoorJWT, "wrong-key", http.StatusUnauthorized, false},
		{"absent", config.MCPDoorJWT, "", http.StatusUnauthorized, false},
		{"configured-principal", "", "", http.StatusOK, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, writer, verify := newMCPV3Stream(t, "listener")
			upstream, calls := principalStateUpstream(t)
			opts := principalStateOpts(t, "")
			opts.Transport, opts.ReceiptV3, opts.RequireReceipts = "mcp_http_listener", writer, true
			token := tc.token
			if tc.doorMode != "" {
				fixture := newDoorFixture(t, tc.doorMode)
				opts.ListenerDoor = fixture.verifier
				if token != "" {
					token = fixture.token(token)
				}
			} else {
				opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
					return ListenerPrincipal{Provider: "configured", Subject: "configured-subject", Epoch: 1}, nil
				}
			}
			base, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			resp := doorRPC(t, base, http.MethodPost, token, principalControlToolCall(1, "read_file", "{}"), func(r *http.Request) {
				r.Header.Set("X-Subject", "forged-subject")
				r.Header.Set("X-Client-ID", "forged-client")
				if token == "" {
					r.Header.Del("Authorization")
				}
			})
			body, readErr := io.ReadAll(resp.Body)
			if err := errors.Join(readErr, resp.Body.Close()); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status {
				t.Fatalf("got HTTP %d, want %d: %s", resp.StatusCode, tc.status, body)
			}
			wantCaller := v3.Caller{Authn: "none"}
			if tc.verified {
				wantCaller = v3.Caller{Authn: "mcp_door_verified", Resource: doorTestResource, Issuer: doorTestIssuer, Subject: "a", ClientID: "cloud"}
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, verify)
			if err != nil || result.Verdict != "VALID" {
				t.Fatalf("invalid receipt stream: %+v (%v)", result, err)
			}
			actions := readMCPV3Actions(t, dir)
			sent, delivered, refused := false, false, false
			for _, action := range actions {
				if action.Caller != wantCaller {
					t.Fatalf("caller = %+v, want %+v", action.Caller, wantCaller)
				}
				sent = sent || action.EffectBoundary == mcpV3Upstream && action.OutcomeClass == "completed"
				delivered = delivered || action.EffectBoundary == mcpV3Delivery && action.OutcomeClass == "completed"
				refused = refused || action.EffectBoundary == mcpV3Upstream && action.Verdict == config.ActionBlock
			}
			if tc.status == http.StatusOK {
				if !sent || !delivered || refused || calls.Load() != 1 {
					t.Fatalf("expected signed send and delivery, got %d upstream calls and %+v", calls.Load(), actions)
				}
			} else if !refused || sent || delivered || calls.Load() != 0 {
				t.Fatalf("expected only a refusal, got %d upstream calls and %+v", calls.Load(), actions)
			}
		})
	}
}

func readMCPV3Actions(t *testing.T, dir string) []v3.Action {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.receipt-v3.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("want one receipt file, got %v (%v)", paths, err)
	}
	f, err := os.Open(filepath.Clean(paths[0]))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	dec := json.NewDecoder(f)
	var actions []v3.Action
	for {
		var envelope struct {
			Payload struct {
				Kind string    `json:"kind"`
				Body v3.Action `json:"body"`
			} `json:"payload"`
		}
		if err := dec.Decode(&envelope); errors.Is(err, io.EOF) {
			return actions
		} else if err != nil {
			t.Fatal(err)
		}
		if envelope.Payload.Kind == "action" {
			actions = append(actions, envelope.Payload.Body)
		}
	}
}

func TestMCPV3StreamTerminalDiagnostic(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		run          func(*testing.T, MCPProxyOpts, receipt.EmitOpts)
		wantParent   bool
	}{
		{"listener", httpstream.Incomplete, func(t *testing.T, opts MCPProxyOpts, parent receipt.EmitOpts) {
			recordListenerStreamError(t.Context(), io.Discard, opts, parent, false, io.ErrUnexpectedEOF)
		}, true},
		{"bridge", httpstream.Cancelled, func(t *testing.T, opts MCPProxyOpts, parent receipt.EmitOpts) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			tracker := NewRequestTracker()
			id := json.RawMessage("1")
			tracker.TrackOutcome(id, TrackedRequestOutcome{Receipt: parent})
			emitTrackedStreamError(ctx, io.Discard, tracker, id, opts, io.ErrUnexpectedEOF)
			if _, pending := tracker.Consume(id); pending {
				t.Error("terminal request stayed in the tracker")
			}
		}, true},
		{"standalone", httpstream.Incomplete, func(_ *testing.T, opts MCPProxyOpts, _ receipt.EmitOpts) {
			emitMCPStandaloneStreamReceipt(opts, io.Discard, mcpStreamReceipt(opts, http.MethodGet), "200", httpstream.Incomplete)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, writer, verify := newMCPV3Stream(t, "listener")
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), Transport: transportMCPStdio,
				RequireReceipts: true, ReceiptV3: writer,
			}
			parent := receipt.EmitOpts{
				ActionID: receipt.NewActionID(), Method: http.MethodPost, Verdict: config.ActionAllow,
				Transport: opts.Transport, Target: "https://upstream.vendor.example",
			}
			var delivery mcpV3Receipt
			if err := opts.confirmV3ResponseDelivery(io.Discard, parent, &delivery); err != nil {
				t.Fatal(err)
			}
			if err := delivery.writeV3Response(opts, io.Discard, v3TestPeer(func([]byte) error { return nil }), []byte(cleanToolsCallResponse)); err != nil {
				t.Fatal(err)
			}
			tc.run(t, opts, parent)
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, verify)
			if err != nil || result.Verdict != "VALID" || !hasMCPV3State(result, "completed") || !hasMCPV3State(result, "blocked") {
				t.Fatalf("delivery or terminal diagnostic failed verification: %+v (%v)", result, err)
			}
			actions := readMCPV3Actions(t, dir)
			if len(actions) != 3 {
				t.Fatalf("expected delivery intent and outcome plus one diagnostic, got %+v", actions)
			}
			got := actions[2]
			if got.ActionID == parent.ActionID || got.Pattern != tc.reason || got.EffectBoundary != mcpV3Delivery ||
				got.EffectRelation != "not_attempted" || got.Attempt != nil || got.OutcomeClass != "" {
				t.Fatalf("invalid terminal diagnostic: %+v", got)
			}
			wantParent := ""
			if tc.wantParent {
				wantParent = parent.ActionID
			}
			if got.ParentActionID != wantParent {
				t.Fatalf("diagnostic parent %q, want %q", got.ParentActionID, wantParent)
			}
		})
	}
}

func TestMCPV3ReceiptFailureStopsInteractiveChild(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("shell subprocess test requires Unix")
	}
	for _, sandboxed := range []bool{false, true} {
		name := "stdio"
		if sandboxed {
			name = "sandbox"
		}
		t.Run(name, func(t *testing.T) {
			_, writer, _ := newMCPV3Stream(t, transportMCPStdio)
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			opts := MCPProxyOpts{
				Scanner: testInputScanner(t), Transport: transportMCPStdio,
				RequireReceipts: true, ReceiptV3: writer,
			}
			clientIn, clientInput := io.Pipe()
			defer func() { _ = clientInput.Close() }()
			defer func() { _ = clientIn.Close() }()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			const script = "printf '%s\\n' '" + cleanToolsCallResponse + "'; read -r line"
			done := make(chan error, 1)
			go func() {
				if sandboxed {
					cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
					done <- RunProxyWithSandbox(ctx, cmd, clientIn, io.Discard, io.Discard, opts)
					return
				}
				done <- RunProxy(ctx, clientIn, io.Discard, io.Discard, []string{"/bin/sh", "-c", script}, opts)
			}()
			timer := time.NewTimer(testwait.Deadline(2 * time.Second))
			defer timer.Stop()
			select {
			case err := <-done:
				if !errors.Is(err, ErrReceiptRequired) {
					t.Fatalf("proxy returned %v, want receipt confirmation error", err)
				}
			case <-timer.C:
				cancel()
				_ = clientIn.Close()
				select {
				case err := <-done:
					t.Logf("proxy returned after test cancellation: %v", err)
				case <-time.After(testwait.Deadline(2 * time.Second)):
					t.Error("proxy did not stop after test cancellation")
				}
				t.Fatal("proxy did not stop the interactive child after receipt confirmation failed")
			}
		})
	}
}

func TestMCPV3ToolListHasOnlySettledDelivery(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string
		ack    bool
	}{
		{"warn", config.ActionWarn, false},
		{"acknowledged", config.ActionBlock, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, writer, verify := newMCPV3Stream(t, transportMCPStdio)
			var acks []config.MCPAcknowledgedFinding
			if tc.ack {
				acks = []config.MCPAcknowledgedFinding{proxyAckEntry(t)}
			}
			opts := MCPProxyOpts{
				Scanner: testScannerWithAction(t, config.ActionWarn),
				ToolCfg: &tools.ToolScanConfig{
					Action: tc.action, CredentialAcks: tools.NewCredentialAckSet(acks, proxyAckKey),
					Now: func() time.Time { return time.Date(2026, 10, 8, 15, 30, 0, 0, time.UTC) },
				},
				Transport: transportMCPStdio, ServerName: proxyAckServer, ServerBinding: proxyAckBinding,
				RequireReceipts: true, ReceiptV3: writer, v3DirectResponseDelivery: true,
			}
			line := `{"jsonrpc":"2.0","id":1,"result":{"tools":[` + proxyAckTool + `]}}` + "\n"
			var out strings.Builder
			_, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(line)), transport.NewStdioWriter(&out), io.Discard, nil, opts)
			if err != nil || !strings.Contains(out.String(), `"store_secret"`) {
				t.Fatalf("inventory delivery failed: %q (%v)", out.String(), err)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			res, err := v3.VerifyPaths(t.Context(), []string{dir}, verify)
			if err != nil || res.Verdict != "VALID" || res.Counts.Decisions == nil {
				t.Fatalf("corpus verification failed: %s, findings %v (%v)", res.Verdict, res.Findings, err)
			}
			for _, count := range *res.Counts.Decisions {
				if count.State == "outcome_unknown" {
					t.Errorf("verified delivery left %d unresolved intent(s)", count.Count)
				}
			}
			actions := readMCPV3Actions(t, dir)
			wantVerdict := config.ActionWarn
			if tc.ack {
				wantVerdict = config.ActionAllow
			}
			if len(actions) != 2 || actions[0].Layer != "mcp_tool_scan" ||
				actions[0].Verdict != wantVerdict || actions[0].Pattern == "" ||
				actions[0].Phase != "intent" || actions[1].ActionID != actions[0].ActionID ||
				actions[1].Phase != "outcome" || actions[1].OutcomeClass != "completed" {
				t.Errorf("expected the tool scan intent and its completed outcome, got %+v", actions)
			}
			if res.Counts.EffectsCompleted == nil || *res.Counts.EffectsCompleted != 1 {
				t.Errorf("expected exactly one completed delivery, decisions=%v", *res.Counts.Decisions)
			}
		})
	}
}

func TestMCPV3HoldResolutionBoundsWriterWait(t *testing.T) {
	entered := make(chan struct{})
	unblock := make(chan struct{})
	release := sync.OnceFunc(func() { close(unblock) })
	var stall atomic.Bool
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	policy := v3.Digest(nil)
	writer, err := v3.OpenStreamWriter(t.Context(), v3.StreamWriterOptions{
		Dir: t.TempDir(), SigningKey: key, PolicyHash: policy,
		Identity: v3.Writer{Instance: "example", Product: "Pipelock", Version: "3"},
		Coverage: v3.Coverage{
			ReceiptsRequired: true, Surfaces: []string{"stdio"},
			RedactionRuleset: v3.Ruleset{ID: "example", Version: "1", Hash: policy},
		},
		Clock: func() time.Time {
			if stall.Swap(false) {
				close(entered)
				<-unblock
			}
			return time.Now()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		release()
		_ = writer.Close(context.Background(), nil)
	})
	opts := MCPProxyOpts{RequireReceipts: true, ReceiptV3: writer, Transport: transportMCPStdio}
	const holdID = "held-action"
	var settlement deferredReceiptSettlement
	hold := settlement.confirmV3Hold(opts, receipt.EmitOpts{
		ActionID: holdID, Target: "tool:lookup", MCPMethod: "tools/call", Transport: transportMCPStdio,
	})
	policyBounds := deferred.NewManager(deferred.Config{Enabled: true, Timeout: 25 * time.Millisecond}).Policy()
	if err := hold(deferred.HeldAction{DeferID: holdID, Deadline: time.Now().Add(time.Second), Policy: policyBounds}); err != nil {
		t.Fatal(err)
	}
	stall.Store(true)
	heartbeat := make(chan error, 1)
	go func() { heartbeat <- writer.WriteHeartbeat(t.Context()) }()
	select {
	case <-entered:
	case <-time.After(testwait.Deadline(time.Second)):
		t.Fatal("heartbeat did not acquire the writer")
	}

	result := make(chan error, 1)
	go func() {
		result <- settlement.settleV3Hold(opts, deferred.Resolution{
			DeferID: holdID, FinalDecision: config.ActionBlock, ResolutionSource: deferred.SourceOperator, Policy: policyBounds,
		})
	}()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrReceiptRequired) {
			t.Fatalf("blocked resolution write: %v", err)
		}
	case <-time.After(testwait.Deadline(time.Second)):
		t.Fatal("hold resolution waited indefinitely for the receipt writer")
	}
	release()
	if err := <-heartbeat; err != nil {
		t.Fatal(err)
	}
}
