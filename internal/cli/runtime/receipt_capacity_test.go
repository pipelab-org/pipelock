// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestSingleReceiptRestartRefusesOverLimitNativePredecessor(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "evidence")
	keyPath := filepath.Join(root, "receipt.key")
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	options := func(evidenceDir string) ServerOpts {
		return ServerOpts{
			ConfigFile: writeServerTestConfig(t, fmt.Sprintf("mode: balanced\nflight_recorder:\n  enabled: true\n  require_receipts: true\n  dir: %q\n  signing_key_path: %q\n", evidenceDir, keyPath)),
			Stdout:     io.Discard, Stderr: io.Discard,
		}
	}

	opts := options(dir)
	first, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	firstSession := first.receiptEmitter.Session()
	signer := first.receiptEmitter.SignerKeyHex()
	if err := first.sealTranscriptRoot(); err != nil {
		t.Fatal(err)
	}
	first.cleanup()
	paths, err := filepath.Glob(filepath.Join(dir, "ael", "*", "recorders", "*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("native streams = %v, err = %v", paths, err)
	}
	run := filepath.Base(filepath.Dir(filepath.Dir(paths[0])))
	if _, err := ael.VerifyRun(dir, run, signer); err != nil {
		t.Fatalf("original predecessor did not verify: %v", err)
	}
	if err := os.Truncate(paths[0], (256<<20)+1); err != nil {
		t.Fatal(err)
	}

	refused, err := NewServer(opts)
	if refused != nil {
		refused.cleanup()
		t.Fatal("opened a successor over an oversized predecessor")
	}
	if !errors.Is(err, ael.ErrStreamTooLarge) || !strings.Contains(err.Error(), "set flight_recorder.dir to a new empty directory") {
		t.Fatalf("startup refusal = %v", err)
	}
	t.Logf("startup refusal = %v", err)
	if _, _, err := runMCPProxyCommand(t, opts.ConfigFile); !errors.Is(err, ael.ErrStreamTooLarge) {
		t.Fatalf("standalone MCP startup refusal = %v", err)
	}
	next, err := NewServer(options(filepath.Join(root, "new-evidence")))
	if err != nil {
		t.Fatalf("new recorder directory did not restore startup: %v", err)
	}
	defer next.cleanup()
	if next.receiptEmitter.Session() == firstSession {
		t.Fatal("new recorder directory reused the refused session")
	}
	if err := next.sealTranscriptRoot(); err != nil {
		t.Fatal(err)
	}
}

func TestReceiptHeartbeatCapacityLeavesEmitterSealable(t *testing.T) {
	const ceiling = 1300
	capacity := ael.NewCapacity(ceiling)
	dir := t.TempDir()
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key, NativeCapacity: capacity})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	var log bytes.Buffer
	startReceiptHeartbeat(ctx, &wg, time.Hour, func() *receipt.Emitter { return e }, &log, true, func(err error) {
		t.Errorf("capacity treated as a persistence failure: %v", err)
	})
	cancel()
	wg.Wait()
	if e.HealthError() != nil || !strings.Contains(log.String(), ael.ErrCapacity.Error()) {
		t.Fatalf("health = %v, heartbeat log = %q", e.HealthError(), log.String())
	}
	if err := emitSessionCloseAndTranscriptRoot(e, e.Session()); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "ael", "*"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("native runs = %v, error = %v", paths, err)
	}
	if head, err := ael.VerifyRun(dir, filepath.Base(paths[0]), e.SignerKeyHex()); err != nil || head.RecordCount != 2 {
		t.Fatalf("verifiable close: head=%+v err=%v", head, err)
	}
}

func TestNativeCapacityStopRefusesReloadWhileAdmissionSettles(t *testing.T) {
	root := t.TempDir()
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "receipt.key")
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	configPath := writeServerTestConfig(t, fmt.Sprintf("flight_recorder:\n  enabled: true\n  dir: %q\n  signing_key_path: %q\n", filepath.Join(root, "evidence"), keyPath))
	s, _ := newTestServerForStart(t, func(opts *ServerOpts) {
		opts.ConfigFile = configPath
		opts.nativeAELCapacityLimit = 3000
	})
	e := s.liveReceiptEmitter()
	capacity := e.NativeCapacity()
	s.receiptRotationRequested.Store(true)
	if err := s.receiptRestartError(capacity); !errors.Is(err, errReceiptGroupKeyRotation) {
		t.Fatalf("key restart = %v", err)
	}
	admitted, err := e.AdmitNative(receipt.EmitOpts{}, 1)
	if err != nil || admitted.NativeLease == nil {
		t.Fatalf("admission = %v, %v", admitted.NativeLease, err)
	}
	defer admitted.ReleaseNativeAdmission()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	read, write := io.Pipe()
	defer func() { _ = read.Close(); _ = write.Close() }()
	var wg sync.WaitGroup
	watchNativeCapacity(ctx, &wg, capacity, cancel, write)
	if _, err := e.ReserveNativeRecords(10); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("capacity admission = %v", err)
	}
	if line, err := bufio.NewReader(read).ReadString('\n'); err != nil || !strings.Contains(line, ael.ErrCapacity.Error()) {
		t.Fatalf("capacity notice = %q, %v", line, err)
	}
	s.reloadMu.Lock()
	reloadErr := s.executeReloadLocked(s.currentConfig(), false, &reloadAttempt{})
	s.reloadMu.Unlock()
	if !errors.Is(reloadErr, ael.ErrCapacity) {
		t.Fatalf("reload = %v", reloadErr)
	}
	if err := s.receiptRestartError(capacity); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("capacity restart = %v", err)
	}
	cancel()
	wg.Wait()
	admitted.ReleaseNativeAdmission()
	if err := s.sealTranscriptRoot(); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedMCPNativeCapacityClosesReceiptGroupAndRestarts(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "evidence")
	keyPath := filepath.Join(root, "receipt.key")
	_, key, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.SavePrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 2)
	upstreamStreamClosed := make(chan struct{})
	var serveSSE atomic.Bool
	release := make(chan struct{})
	releaseUpstream := sync.OnceFunc(func() { close(release) })
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		const reply = `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`
		if serveSSE.Load() {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "data: %s\n\n", reply)
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			<-r.Context().Done()
			close(upstreamStreamClosed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(releaseUpstream)
	slot := ael.ActivityRecordLimit(len(receipt.ActionUnclassified), 36)
	configPath := writeServerTestConfig(t, fmt.Sprintf("mode: balanced\nflight_recorder:\n  enabled: true\n  sign_checkpoints: true\n  receipt_chains: 2\n  require_receipts: true\n  dir: %q\n  signing_key_path: %q\n", dir, keyPath))
	newServer := func(slots int64) (*Server, *syncBuffer) {
		return newTestServerForStart(t, func(o *ServerOpts) {
			o.ConfigFile = configPath
			o.Listen, o.ListenChanged = serverTestEphemeralListen, true
			o.MCPListen, o.MCPUpstream = serverTestEphemeralListen, upstream.URL
			o.nativeAELCapacityLimit = slots*slot + 2048
		})
	}
	waitListener := func(buf *syncBuffer) string {
		const marker = "MCP reverse proxy listening on "
		waitForServerOutput(t, buf, marker)
		_, addr, _ := strings.Cut(buf.String(), marker)
		addr, _, _ = strings.Cut(addr, "\n")
		return "http://" + strings.TrimSpace(addr)
	}
	type result struct {
		code int
		body string
		err  error
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	startPost := func(base string) (*http.Response, error) {
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`))
		if requestErr != nil {
			return nil, requestErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		return upstream.Client().Do(req)
	}
	post := func(base string) result {
		resp, requestErr := startPost(base)
		if requestErr != nil {
			return result{err: requestErr}
		}
		defer func() { _ = resp.Body.Close() }()
		body, readErr := io.ReadAll(resp.Body)
		return result{code: resp.StatusCode, body: string(body), err: readErr}
	}
	waitEffect := func() {
		t.Helper()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("upstream did not observe the admitted request")
		}
	}
	s, logs := newServer(100)
	open, _ := s.receiptShardSet.Opening()
	shards := s.receiptShardSet
	run := runJoined(t, ctx, s.Start, releaseUpstream)
	base := waitListener(logs)
	admitted := make(chan result, 1)
	go func() { admitted <- post(base) }()
	select {
	case <-entered:
	case early := <-admitted:
		t.Fatalf("admitted request ended before upstream effect: %+v", early)
	case <-ctx.Done():
		t.Fatal("upstream did not observe the admitted request")
	}
	if refused := post(base); refused.err != nil || refused.code != http.StatusServiceUnavailable || !strings.Contains(refused.body, ael.ErrCapacity.Error()) {
		t.Fatalf("capacity refusal: %+v", refused)
	}
	if _, err := shards.AdmitNative(receipt.EmitOpts{ShardSelected: true, ShardIndex: 1}, 1); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("other shard admission after stop: %v", err)
	}
	select {
	case <-entered:
		t.Fatal("refused request reached the upstream")
	default:
	}
	releaseUpstream()
	if first := <-admitted; first.err != nil || first.code != http.StatusOK || !strings.Contains(first.body, "result") {
		t.Fatalf("admitted reply: %+v", first)
	}
	if err := <-run; !errors.Is(err, ael.ErrCapacity) || cliutil.ExitCodeOf(err) != 1 {
		t.Fatalf("capacity restart result: %v", err)
	}
	trusted := []string{open.SignerKey}
	if got := receipt.VerifyReceiptGroup(dir, open.GroupID, trusted); got.Verdict != receipt.GroupValid {
		t.Fatalf("closed group: %+v", got)
	}
	t.Logf("HTTP 503 %q, admitted HTTP 200, runtime returned %v (exit 1), group %s", ael.ErrCapacity, ael.ErrCapacity, receipt.GroupValid)

	serveSSE.Store(true)
	restarted, restartedLogs := newServer(128)
	next, _ := restarted.receiptShardSet.Opening()
	if next.PreviousGroupID != open.GroupID || next.GroupID == open.GroupID {
		t.Fatalf("restart did not bind a new group to the closed run: %+v", next)
	}
	run = runJoined(t, ctx, restarted.Start, nil)
	base = waitListener(restartedLogs)
	stream, err := startPost(base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Body.Close() }()
	waitEffect()
	reader := bufio.NewReader(stream.Body)
	firstEvent, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(firstEvent, "result") {
		t.Fatalf("first admitted SSE event: %q, %v", firstEvent, err)
	}
	if refused := post(base); refused.err != nil || refused.code != http.StatusServiceUnavailable || !strings.Contains(refused.body, ael.ErrCapacity.Error()) {
		t.Fatalf("SSE capacity refusal: %+v", refused)
	}
	select {
	case <-upstreamStreamClosed:
	case <-ctx.Done():
		t.Fatal("capacity stop did not close the upstream SSE connection")
	}
	if rest, _ := io.ReadAll(reader); strings.Contains(string(rest), "data:") {
		t.Fatalf("unexpected SSE event after capacity stop: %q", rest)
	}
	if err := <-run; !errors.Is(err, ael.ErrCapacity) || cliutil.ExitCodeOf(err) != 1 {
		t.Fatalf("SSE capacity restart result: %v", err)
	}
	entries, err := recorder.QuerySession(dir, next.Shards[next.ProcessShardIndex].SessionID, &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries.Entries {
		if strings.Contains(string(entry.RawDetail), "reason=native_ael_capacity") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("capacity stop did not sign an SSE terminal receipt")
	}
	t.Log("successor served an SSE event, closed the upstream on capacity, and signed the terminal receipt")
	if got := receipt.VerifyReceiptGroup(dir, next.GroupID, trusted); got.Verdict != receipt.GroupValid {
		t.Fatalf("closed successor group: %+v", got)
	}
}
