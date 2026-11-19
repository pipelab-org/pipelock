// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestStdioNativeCapacitySettlesAdmittedReply(t *testing.T) {
	e, dir := newNativeMCPEmitter(t, nativeMCPRequestRecords+4)
	capacity := e.NativeCapacity()
	input, upstream := io.Pipe()
	defer func() { _ = input.Close() }()
	defer func() { _ = upstream.Close() }()
	tracker := NewRequestTracker()
	blocked := make(chan BlockedRequest, 2)
	opts := MCPProxyOpts{
		Scanner: testInputScanner(t), Transport: transportMCPStdio,
		ReceiptEmitter: e, RequireReceipts: true, nativeStdio: true,
	}
	const call = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
	const secondCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
	const reply = `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = upstream.Close() }()
		ForwardScannedInput(transport.NewStdioReader(strings.NewReader(call+"\n"+secondCall)), transport.NewStdioWriter(upstream),
			io.Discard, config.ActionWarn, config.ActionBlock, blocked, nil, tracker, opts)
	}()
	select {
	case denial := <-blocked:
		t.Fatalf("first call ended before effect: %+v", denial)
	default:
	}
	reader := transport.NewStdioReader(input)
	got, err := reader.ReadMessage()
	if err != nil || !bytes.Contains(got, []byte(`"id":1`)) {
		t.Fatalf("first upstream message = %q, %v", got, err)
	}
	select {
	case denial := <-blocked:
		if string(denial.ID) != "2" || !strings.Contains(denial.ErrorMessage, ael.ErrCapacity.Error()) {
			t.Fatalf("second call refusal = %+v", denial)
		}
	case <-t.Context().Done():
		t.Fatal("second call did not receive a refusal")
	}
	if _, err := reader.ReadMessage(); !errors.Is(err, io.EOF) {
		t.Fatalf("refused call reached upstream: %v", err)
	}
	<-done
	select {
	case <-capacity.Drained():
		t.Fatal("unsettled stdio response did not keep its reservation")
	default:
	}
	var client bytes.Buffer
	if _, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(reply)), transport.NewStdioWriter(&client), io.Discard, tracker, opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(client.String(), reply) {
		t.Fatalf("client response = %q", client.String())
	}
	select {
	case <-capacity.Drained():
	default:
		t.Fatal("stdio capacity did not drain after settling its response")
	}
	verifyMCPNativeClose(t, e, dir)
}

func TestStdioNativeCapacityStopsIdleInput(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("shell subprocess test requires unix")
	}
	const request = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
	const reply = `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`
	const late = `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"after capacity"}}`
	const script = `
IFS= read -r request || exit 2
case "$request" in *'"id":1'*) ;; *) exit 3;; esac
printf '%s\n' "$1"
if IFS= read -r request; then exit 4; fi
printf '%s\n' "$2"
`
	for _, mode := range []string{"subprocess", "sandboxed"} {
		t.Run(mode, func(t *testing.T) {
			e, dir := newNativeMCPEmitter(t, nativeMCPRequestRecords+4)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			input, client := io.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = input.Close() }()
			var out lockedHTTPBuffer
			opts := MCPProxyOpts{Scanner: testInputScanner(t), ReceiptEmitter: e, RequireReceipts: true}
			done := make(chan error, 1)
			go func() {
				args := []string{"sh", "-c", script, "sh", reply, late}
				if mode == "sandboxed" {
					cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec // fixed test command
					done <- RunProxyWithSandbox(ctx, cmd, input, &out, io.Discard, opts)
					return
				}
				done <- RunProxy(ctx, input, &out, io.Discard, args, opts)
			}()
			if _, err := io.WriteString(client, request+"\n"); err != nil {
				t.Fatal(err)
			}
			testwait.For(t, time.Second, func() bool { return out.contains(reply) }, "subprocess response forwarded")
			if _, err := e.ReserveNativeRecords(2 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
				t.Fatalf("capacity admission = %v", err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, ael.ErrCapacity) {
					t.Fatalf("capacity result = %v", err)
				}
			case <-ctx.Done():
				t.Fatal("proxy did not stop with stdin open")
			}
			if out.contains(late) {
				t.Fatalf("unadmitted message delivered: %s", out.String())
			}
			select {
			case <-e.NativeCapacity().Drained():
			default:
				t.Fatal("stdio leases did not settle")
			}
			verifyMCPNativeClose(t, e, dir)
		})
	}
}

func newNativeMCPEmitter(t *testing.T, slots int64) (*receipt.Emitter, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	slot := ael.ActivityRecordLimit(len(receipt.ActionUnclassified), 36)
	capacity := ael.NewCapacity(slots*slot + 2048)
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key, Session: session, NativeCapacity: capacity})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	return e, dir
}

func verifyMCPNativeClose(t *testing.T, e *receipt.Emitter, dir string) {
	t.Helper()
	if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
		t.Fatal(err)
	}
	runs, err := filepath.Glob(filepath.Join(dir, "ael", "*"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("native evidence paths %v, error %v", runs, err)
	}
	if _, err := ael.VerifyRun(dir, filepath.Base(runs[0]), e.SignerKeyHex()); err != nil {
		t.Fatalf("verify native close: %v", err)
	}
}

func TestHTTPBridgeNativeCapacityClosesPostStream(t *testing.T) {
	testHTTPBridgeNativeCapacityClosesStream(t, http.MethodPost)
}

func TestHTTPBridgeNativeCapacityClosesGetStream(t *testing.T) {
	testHTTPBridgeNativeCapacityClosesStream(t, http.MethodGet)
}

func testHTTPBridgeNativeCapacityClosesStream(t *testing.T, method string) {
	t.Helper()
	e, dir := newNativeMCPEmitter(t, nativeMCPRequestRecords+nativeMCPEventRecords+4)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	const call = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
	reply := `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`
	if method == http.MethodGet {
		reply = `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"fixture"}}`
	}
	type upstreamRequest struct{ method, body string }
	request := make(chan upstreamRequest, 1)
	closed := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bytes, _ := io.ReadAll(r.Body)
		request <- upstreamRequest{method: r.Method, body: string(bytes)}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: "+reply+"\n\n")
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		<-r.Context().Done()
		close(closed)
	}))
	defer upstream.Close()
	defer cancel()
	opts := MCPProxyOpts{
		Scanner: testInputScanner(t), Transport: "mcp_http",
		ReceiptEmitter: e, RequireReceipts: true, AuthorityDestination: upstream.URL,
	}
	clientRead, clientWrite := io.Pipe()
	defer func() { _ = clientRead.Close() }()
	done := make(chan error, 1)
	go func() {
		defer func() { _ = clientWrite.Close() }()
		if method == http.MethodGet {
			scanErr, setupErr := scanGETStream(ctx, transport.NewHTTPClient(upstream.URL, nil), transport.NewStdioWriter(clientWrite), io.Discard, opts, NewStrictRequestTracker())
			done <- errors.Join(scanErr, setupErr)
			return
		}
		done <- RunHTTPProxy(ctx, strings.NewReader(call), clientWrite, io.Discard, upstream.URL, nil, opts)
	}()
	select {
	case got := <-request:
		if got.method != method || (method == http.MethodPost && !strings.Contains(got.body, `"method":"tools/call"`)) {
			t.Fatalf("upstream effect = %+v", got)
		}
	case err := <-done:
		t.Fatalf("proxy ended before upstream effect: %v", err)
	case <-ctx.Done():
		t.Fatal("upstream did not receive call")
	}
	reader := bufio.NewReader(clientRead)
	if got, err := reader.ReadString('\n'); err != nil || !strings.Contains(got, reply) {
		t.Fatalf("admitted SSE event = %q, %v", got, err)
	}
	if _, err := e.ReserveNativeRecords(nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("new unit after reservation: %v", err)
	}
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("capacity stop did not close the upstream stream")
	}
	select {
	case err := <-done:
		if !errors.Is(err, ael.ErrCapacity) {
			t.Fatalf("HTTP bridge result = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("HTTP bridge did not return after capacity stop")
	}
	verifyMCPNativeClose(t, e, dir)
	entries, err := recorder.QuerySession(dir, e.Session(), &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries.Entries {
		signed, err := receipt.Unmarshal(entry.RawDetail)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(signed.ActionRecord.Pattern, "reason=native_ael_capacity") {
			if err := receipt.VerifyWithKey(signed, e.SignerKeyHex()); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("missing signed capacity outcome")
}

func TestDeferredNativeReservationSettlesAtCapacity(t *testing.T) {
	e, dir := newNativeMCPEmitter(t, nativeMCPRequestRecords+4)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	manager := deferred.NewManager(deferred.Config{
		Enabled: true, Timeout: time.Minute, MaxPending: 1, MaxPendingPerSession: 1, MaxPendingBytes: 1024,
	})
	t.Cleanup(func() { manager.ResolveAll(config.ActionBlock, deferred.SourceCancel) })
	opts := MCPProxyOpts{ReceiptEmitter: e, Transport: transportMCPStdio, DeferManager: manager, RequireReceipts: true}
	admission, err := opts.admitNativeRequest()
	if err != nil {
		t.Fatal(err)
	}
	opts.nativeAdmission = admission
	heldOpts, finishHeld, err := opts.splitDeferredAdmission()
	if err != nil {
		t.Fatal(err)
	}
	defer finishHeld()
	result := make(chan error, 1)
	if err := manager.Hold(deferred.HeldAction{
		DeferID: receipt.NewActionID(), Target: "fixture", Method: methodToolsCall,
		Resolve: func(res deferred.Resolution) {
			defer finishHeld()
			result <- EmitDeferredResolutionReceipt(heldOpts, io.Discard, res)
		},
	}); err != nil {
		t.Fatal(err)
	}
	admission.ReleaseNativeAdmission()
	if _, err := opts.admitNativeRequest(); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("new unit after held reservation: %v", err)
	}
	watchCapacityDeferrals(ctx, opts)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("capacity cancellation could not sign deferred resolution: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("capacity did not settle the deferred call")
	}
	select {
	case <-e.NativeCapacity().Drained():
	default:
		t.Fatal("settled deferred call retained capacity")
	}
	verifyMCPNativeClose(t, e, dir)
}
