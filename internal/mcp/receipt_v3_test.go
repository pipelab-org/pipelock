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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type v3TestPeer func([]byte) error

func (f v3TestPeer) WriteMessage(msg []byte) error { return f(msg) }

func TestMCPV3ConfirmsUpstreamSend(t *testing.T) {
	for _, surface := range []string{"stdio", "bridge", "listener"} {
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
	dir, writer, verify := newMCPV3Stream(t, surface)
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
			if !isMCPUpstreamRequest(r) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			observe(r.Context())
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
			status, body := postToolsCall(t, url)
			if strings.Contains(body, "result") != live {
				t.Fatalf("unexpected listener reply %d %s", status, body)
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
	if err != nil || result.Verdict != "VALID" || !hasMCPV3State(result, "completed") {
		t.Fatalf("upstream outcome not recorded: %+v (%v)", result, err)
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
			if err != nil || result.Verdict != "VALID" || !hasMCPV3State(result, "completed") {
				t.Fatalf("held call did not settle: %+v (%v)", result, err)
			}
		})
	}
}
