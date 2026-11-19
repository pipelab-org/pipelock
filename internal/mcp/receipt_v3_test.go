// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
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
