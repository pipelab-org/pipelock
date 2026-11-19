// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/evidence/completeness"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func observeSignedIntentAtWrite(t *testing.T, dir, key string, isRequest func([]byte) bool) (func(context.Context, string, string) (net.Conn, error), <-chan struct{}) {
	t.Helper()
	observed := make(chan struct{})
	check := sync.OnceFunc(func() {
		defer close(observed)
		records, err := receipt.ExtractReceipts(filepath.Join(dir, "evidence-proxy-0.jsonl"))
		if err != nil || len(records) != 1 || records[0].ActionRecord.DecisionPhase != receipt.DecisionPhaseIntent {
			t.Errorf("upstream write started without one signed intent: records=%d error=%v", len(records), err)
			return
		}
		if err := receipt.VerifyWithKey(records[0], key); err != nil {
			t.Errorf("verify intent at upstream write: %v", err)
		}
	})
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return upstreamWriteObserver{Conn: c, beforeWrite: func(b []byte) {
			if isRequest(b) {
				check()
			}
		}}, nil
	}
	return dial, observed
}

func requireObservedUpstreamWrite(t *testing.T, observed <-chan struct{}) {
	t.Helper()
	select {
	case <-observed:
	default:
		t.Error("upstream request arrived without a socket write observation")
	}
}

func TestOptionalBridgeIntentPrecedesUpstreamResponse(t *testing.T) {
	arrived := make(chan struct{})
	reply := make(chan struct{})
	release := sync.OnceFunc(func() { close(reply) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(arrived)
		<-reply
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(release)
	emitter, _, dir, key := newReceiptTestHarness(t)
	dial, beforeWrite := observeSignedIntentAtWrite(t, dir, key, func(b []byte) bool { return bytes.HasPrefix(b, []byte("POST ")) })
	opts := MCPProxyOpts{Scanner: testInputScanner(t), ReceiptEmitter: emitter, TaintCfg: &config.Defaults().Taint, DialContext: dial}
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPProxy(ctx, strings.NewReader(deferKillTestCall), io.Discard, io.Discard, server.URL, nil, opts)
	}()
	select {
	case <-arrived:
		requireObservedUpstreamWrite(t, beforeWrite)
	case err := <-done:
		t.Fatalf("bridge exited before upstream saw the request: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence-proxy-0.jsonl")); err != nil {
		t.Fatalf("upstream received the request before the recorder produced evidence: %v", err)
	}
	records := readActionReceipts(t, dir)
	if len(records) != 1 || records[0].ActionRecord.DecisionPhase != receipt.DecisionPhaseIntent {
		t.Fatalf("upstream received the request with %d records and no confirmed intent", len(records))
	}
	if err := receipt.VerifyWithKey(records[0], key); err != nil {
		t.Fatal(err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	paired := readActionReceipts(t, dir)
	if len(paired) != 2 || paired[1].ActionRecord.DecisionPhase != receipt.DecisionPhaseOutcome ||
		paired[1].ActionRecord.ActionID != records[0].ActionRecord.ActionID {
		t.Fatalf("response did not settle the intent once: %d records", len(paired))
	}
}

func TestOptionalBridgeKilledAtUpstreamLeavesSignedIntent(t *testing.T) {
	const childDirEnv = "PIPELOCK_TEST_BRIDGE_KILL_EVIDENCE"
	const upstreamEnv = "PIPELOCK_TEST_BRIDGE_KILL_UPSTREAM"
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	if dir := os.Getenv(childDirEnv); dir != "" {
		r, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, priv)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		em := receipt.NewEmitter(receipt.EmitterConfig{Recorder: r, PrivKey: priv, ConfigHash: mcpTestPolicyHash, Principal: "local", Actor: "pipelock"})
		if err := em.EmitSessionOpen(); err != nil {
			t.Fatal(err)
		}
		opts := MCPProxyOpts{Scanner: testInputScanner(t), ReceiptEmitter: em, TaintCfg: &config.Defaults().Taint, PolicyHash: mcpTestPolicyHash}
		if err := RunHTTPProxy(t.Context(), strings.NewReader(deferKillTestCall), io.Discard, io.Discard, os.Getenv(upstreamEnv), nil, opts); err != nil {
			t.Fatal(err)
		}
		return
	}

	arrived := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(arrived)
		<-r.Context().Done()
	}))
	t.Cleanup(upstream.Close)
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(10*time.Second))
	defer cancel()
	dir := t.TempDir()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, bin, "-test.run=^TestOptionalBridgeKilledAtUpstreamLeavesSignedIntent$") // #nosec G204 -- re-executes the current test binary.
	child.Env = append(os.Environ(), childDirEnv+"="+dir, upstreamEnv+"="+upstream.URL)
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case <-arrived:
	case err := <-done:
		t.Fatalf("bridge exited before reaching upstream: %v\n%s", err, &output)
	case <-ctx.Done():
		waitErr := <-done
		t.Fatalf("upstream never received request: %v (bridge exit: %v)\n%s", ctx.Err(), waitErr, &output)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("bridge exited normally instead of being killed during the request")
	}

	records := readActionReceipts(t, dir)
	if len(records) != 2 || records[1].ActionRecord.DecisionPhase != receipt.DecisionPhaseIntent {
		t.Fatalf("killed bridge left %d records, want session open and intent", len(records))
	}
	chain := receipt.VerifyChainTrusted(records, []string{fmt.Sprintf("%x", priv.Public())})
	report := completeness.Analyze(records, chain)
	if report.Status != completeness.StatusLimited || report.Reason != completeness.ReasonOpenAction {
		t.Fatalf("interrupted request completeness = %s/%s, want an open action", report.Status, report.Reason)
	}
}

func TestOptionalFailedIntentStillSendsWithoutAnOutcome(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)
	h.v1.MarkUnhealthy(io.ErrClosedPipe)
	upstream, calls := countingUpstream(t)
	var logs, output bytes.Buffer
	opts := MCPProxyOpts{Scanner: testInputScanner(t), ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2, PolicyHash: mcpTestPolicyHash}
	if err := RunHTTPProxy(t.Context(), strings.NewReader(deferKillTestCall), &output, &logs, upstream.URL, nil, opts); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !strings.Contains(output.String(), "result") {
		t.Fatalf("upstream calls=%d, output=%q", calls.Load(), &output)
	}
	if got := strings.Join(v2Verdicts(t, h), ","); got != "allow" {
		t.Fatalf("phase-less v2 records = %q, want the admission only", got)
	}
	if records := readActionReceipts(t, h.dir); len(records) != 0 {
		t.Fatalf("failed intent created %d v1 records", len(records))
	}
}

func TestOwnedOutcomeStaysOnAdmissionWriter(t *testing.T) {
	old := newMCPDecisionReceiptHarness(t)
	replacement := newMCPDecisionReceiptHarness(t)
	var outcome TrackedRequestOutcome
	opts := MCPProxyOpts{ReceiptEmitter: old.v1, V2ReceiptEmitter: old.v2, PolicyHash: mcpTestPolicyHash}
	if err := emitMCPToolReceipt(mcpToolReceiptOpts{
		ProxyOpts: opts, Log: io.Discard, Outcome: &outcome, ActionID: receipt.NewActionID(),
		Verdict: config.ActionAllow, Transport: "mcp_stdio", MCPMethod: methodToolsCall, ToolName: "echo",
	}); err != nil {
		t.Fatal(err)
	}
	opts.ReceiptEmitter, opts.V2ReceiptEmitter = replacement.v1, replacement.v2
	if !outcome.settle(io.Discard, opts, "ok", 4, "complete") {
		t.Fatal("confirmed intent missed settlement after reload")
	}
	if outcome.settle(io.Discard, opts, "error", -1, "late_timeout") {
		t.Fatal("second settlement was accepted")
	}
	if records := readActionReceipts(t, old.dir); len(records) != 2 || records[0].ActionRecord.ActionID != records[1].ActionRecord.ActionID {
		t.Fatalf("old writer records = %d, want a pair", len(records))
	}
	if _, err := os.Stat(filepath.Join(replacement.dir, "evidence-proxy-0.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement writer was touched: %v", err)
	}
}

func TestRequiredBridgeNativeWriteFailureLeavesOpenIntent(t *testing.T) {
	emitter, _, dir, key := newReceiptTestHarness(t)
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if err := emitter.AbortNativeAEL(); err != nil {
		t.Fatal(err)
	}
	var sends atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sends.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(upstream.Close)
	opts := MCPProxyOpts{Scanner: testInputScanner(t), ReceiptEmitter: emitter, RequireReceipts: true}
	var out, logs bytes.Buffer
	if err := RunHTTPProxy(t.Context(), strings.NewReader(deferKillTestCall), &out, &logs, upstream.URL, nil, opts); err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 0 || emitter.HealthError() == nil || !strings.Contains(out.String(), "-32007") {
		t.Fatalf("sends=%d writer health=%v reply=%q logs=%q", sends.Load(), emitter.HealthError(), out.String(), logs.String())
	}
	records := readActionReceipts(t, dir)
	if len(records) != 2 || records[1].ActionRecord.DecisionPhase != receipt.DecisionPhaseIntent {
		t.Fatalf("want session open and one unmatched intent, got %+v", records)
	}
	report := completeness.Analyze(records, receipt.VerifyChainTrusted(records, []string{key}))
	if report.Status != completeness.StatusLimited || report.Reason != completeness.ReasonOpenAction {
		t.Fatalf("completeness = %s/%s, want LIMITED/open_action", report.Status, report.Reason)
	}
}

func TestRequiredOutcomeConfirmsSync(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)
	var synced atomic.Bool
	h.rec.SetSyncForTest(func(f *os.File) error {
		if err := f.Sync(); err != nil {
			return err
		}
		entries, err := recorder.ReadEntries(f.Name())
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Type == actionReceiptEntryType {
				r, err := receipt.Unmarshal(entry.RawDetail)
				if err != nil {
					return err
				}
				if r.ActionRecord.DecisionPhase == receipt.DecisionPhaseOutcome {
					synced.Store(true)
				}
			}
		}
		return nil
	})
	opts := MCPProxyOpts{ReceiptEmitter: h.v1, V2ReceiptEmitter: h.v2, RequireReceipts: true}
	var outcome TrackedRequestOutcome
	if _, err := opts.emitReceiptDecision(MCPDecision{
		Receipt: receipt.EmitOpts{
			ActionID: "required-outcome", Target: "tool:confirm", Verdict: config.ActionAllow,
			Transport: "mcp_stdio", PolicyHash: mcpTestPolicyHash, MCPMethod: methodToolsCall,
		},
		RequireReceipt: true, RequiredMode: true, outcome: &outcome,
	}); err != nil {
		t.Fatal(err)
	}
	if !outcome.settle(io.Discard, opts, "result", 4, "complete") || !synced.Load() {
		t.Fatal("required outcome returned without sync confirmation")
	}
}

func TestOptionalWebSocketIntentPrecedesFrameResponse(t *testing.T) {
	emitter, _, dir, signer := newReceiptTestHarness(t)
	type observation struct {
		entries []recorder.Entry
		err     error
	}
	observed := make(chan observation, 1)
	upstream := wsRespondServer(t, []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`), nil, func() {
		entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-proxy-0.jsonl"))
		observed <- observation{entries: entries, err: err}
	})
	t.Cleanup(upstream.Close)
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
	defer cancel()
	input, send := io.Pipe()
	t.Cleanup(func() { _ = send.Close() })
	var out syncBuffer
	dial, beforeWrite := observeSignedIntentAtWrite(t, dir, signer, func(b []byte) bool { return len(b) != 0 && b[0] == 0x81 })
	opts := MCPProxyOpts{Scanner: testScannerForWS(t), ReceiptEmitter: emitter, TaintCfg: &config.Defaults().Taint, DialContext: dial}
	done := make(chan error, 1)
	go func() { done <- RunWSProxy(ctx, input, &out, io.Discard, wsURL(upstream), opts) }()
	if _, err := io.WriteString(send, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-observed:
		requireObservedUpstreamWrite(t, beforeWrite)
		if got.err != nil || len(got.entries) != 1 {
			t.Fatalf("upstream observed frame before a signed receipt: entries=%d error=%v", len(got.entries), got.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	testwait.For(t, time.Second, func() bool { return strings.Contains(out.String(), "result") }, "client response")
	_ = send.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	records := readActionReceipts(t, dir)
	if len(records) != 2 || records[0].ActionRecord.DecisionPhase != receipt.DecisionPhaseIntent ||
		records[1].ActionRecord.DecisionPhase != receipt.DecisionPhaseOutcome || records[0].ActionRecord.ActionID != records[1].ActionRecord.ActionID {
		t.Fatalf("WebSocket request did not produce an intent/outcome pair: %d records", len(records))
	}
	if err := receipt.VerifyWithKey(records[0], signer); err != nil {
		t.Fatal(err)
	}
}
