// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestStdioNativeCapacitySettlesAdmittedReply(t *testing.T) {
	t.Run("intent", func(t *testing.T) { testStdioNativeCapacitySettlesAdmittedReply(t, false) })
	t.Run("warned_and_redacted", func(t *testing.T) { testStdioNativeCapacitySettlesAdmittedReply(t, true) })
}

func testStdioNativeCapacitySettlesAdmittedReply(t *testing.T, warn bool) {
	t.Helper()
	e, dir := newNativeMCPEmitter(t, nativeMCPRequestRecords+4)
	capacity := e.NativeCapacity()
	input, upstream := io.Pipe()
	defer func() { _ = input.Close() }()
	defer func() { _ = upstream.Close() }()
	tracker := NewRequestTracker()
	blocked := make(chan BlockedRequest, 2)
	sc, fixtureInput := nativeMCPFindingScanner(t, e)
	risk := &taintRecorder{}
	cfg := config.Defaults()
	opts := MCPProxyOpts{
		Scanner: sc, Transport: transportMCPStdio, RedactMatcher: testRedactionMatcher(),
		ReceiptEmitter: e, RequireReceipts: true, nativeStdio: true,
		Rec: risk, TaintCfg: &cfg.Taint, TaintExternalSource: true,
	}
	const clean = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
	call := clean
	redactValue := "AIza" + strings.Repeat("A", 35)
	wantRequest, wantReply := 1, 2
	if warn {
		call = makeRequest(1, methodToolsCall, map[string]any{
			"name": "echo", "arguments": map[string]string{"prompt": fixtureInput + " " + redactValue},
		})
		wantRequest, wantReply = receipt.DLPWarningSlots+1, 1
	}
	const secondCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
	const reply = `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"fixture reply finding"}]}}`
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
		t.Fatalf("first upstream call was not delivered: %v", err)
	}
	if warn && (bytes.Contains(got, []byte(redactValue)) || !bytes.Contains(got, []byte("<pl:google-api-key:"))) {
		t.Fatal("first upstream call was not redacted")
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
	requestRecords := mcpNativeRecordCount(t, e, dir, false)
	if requestRecords != wantRequest {
		t.Fatalf("stdio call: wrote %d native records, want %d", requestRecords, wantRequest)
	}
	select {
	case <-capacity.Drained():
		t.Fatal("unsettled stdio response did not keep its reservation")
	default:
	}
	const serverRequest = `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	var client bytes.Buffer
	found, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(serverRequest+"\n"+reply)), transport.NewStdioWriter(&client), io.Discard, tracker, opts)
	if err != nil || !found {
		t.Fatalf("scan of warned response: finding=%t error=%v", found, err)
	}
	if observed := risk.RiskSnapshot(); !observed.Contaminated || observed.Level < session.TaintExternalUntrusted {
		t.Fatalf("MCP reply did not apply external taint: %+v", observed)
	}
	if strings.Contains(client.String(), serverRequest) {
		t.Fatalf("server request used the pending response reservation: %s", client.String())
	}
	if !strings.Contains(client.String(), reply) {
		t.Fatalf("client response = %q", client.String())
	}
	select {
	case <-capacity.Drained():
	default:
		t.Fatal("stdio capacity did not drain after settling its response")
	}
	records := verifyMCPNativeClose(t, e, dir)
	if records-requestRecords != wantReply {
		t.Fatalf("stdio reply: wrote %d native records, want %d", records-requestRecords, wantReply)
	}
	assertMCPNativeRecordBudget(t, "stdio tracked reply", records-requestRecords, nativeMCPPendingRecords)
	assertMCPNativeRecordBudget(t, "stdio call and response", records, nativeMCPRequestRecords)
}

func TestStdioNativeCapacityStopsIdleInput(t *testing.T) {
	testStdioNativeCapacityStopsChild(t, false)
}

func TestStdioNativeCapacityStopsChildThatIgnoresEOF(t *testing.T) {
	testStdioNativeCapacityStopsChild(t, true)
}

func testStdioNativeCapacityStopsChild(t *testing.T, ignoresEOF bool) {
	t.Helper()
	if runtime.GOOS == osWindows {
		t.Skip("shell subprocess test requires unix")
	}
	const request = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
	const reply = `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`
	const late = `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"after capacity"}}`
	script := `
IFS= read -r request || exit 2
case "$request" in *'"id":1'*) ;; *) exit 3;; esac
printf '%s\n' "$1"
if IFS= read -r request; then exit 4; fi
printf '%s\n' "$2"
`
	if ignoresEOF {
		script += "exec sleep 30\n"
	}
	for _, mode := range []string{"subprocess", "sandboxed"} {
		t.Run(mode, func(t *testing.T) {
			e, dir := newNativeMCPEmitter(t, nativeMCPRequestRecords+4)
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(8*time.Second))
			defer cancel()
			input, client := io.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = input.Close() }()
			var out lockedHTTPBuffer
			const grace = 100 * time.Millisecond
			opts := MCPProxyOpts{Scanner: testInputScanner(t), ReceiptEmitter: e, RequireReceipts: true, ListenerShutdownTimeout: grace}
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
			stoppedAt := time.Now()
			if _, err := e.ReserveNativeRecords(2 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
				t.Fatalf("capacity admission = %v", err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, ael.ErrCapacity) {
					t.Fatalf("capacity result = %v", err)
				}
			case <-time.After(testwait.Deadline(time.Second)):
				t.Fatal("proxy did not stop with stdin open")
			}
			if ignoresEOF && time.Since(stoppedAt) < grace {
				t.Fatal("subprocess exited before the capacity grace")
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

func verifyMCPNativeClose(t *testing.T, e *receipt.Emitter, dir string) int {
	t.Helper()
	if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
		t.Fatal(err)
	}
	return mcpNativeRecordCount(t, e, dir, true)
}

func mcpNativeRecordCount(t *testing.T, e *receipt.Emitter, dir string, closed bool) int {
	t.Helper()
	runs, err := filepath.Glob(filepath.Join(dir, "ael", "*"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("native evidence paths %v, error %v", runs, err)
	}
	run := filepath.Base(runs[0])
	verify := ael.VerifyPresentRun
	controlRecords := 1
	if closed {
		verify = ael.VerifyRun
		controlRecords++
	}
	head, err := verify(dir, run, e.SignerKeyHex())
	if err != nil {
		t.Fatalf("verify native run: %v", err)
	}
	if head.RecordCount <= math.MaxInt {
		return int(head.RecordCount) - controlRecords
	}
	t.Fatalf("unexpected native record count %d", head.RecordCount)
	return 0
}

func nativeMCPFindingScanner(t *testing.T, e *receipt.Emitter) (*scanner.Scanner, string) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionWarn
	const responseFinding = "fixture reply finding"
	cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{Name: responseFinding, Regex: responseFinding})
	var markers []string
	for i := range receipt.DLPWarningSlots {
		marker := fmt.Sprintf("FIXTURE-ADVISORY-%02d", i)
		markers = append(markers, marker)
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
			Name: fmt.Sprintf("fixture advisory %d", i), Regex: marker, Severity: config.SeverityLow, Action: config.ActionWarn,
		})
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	sc.SetDLPWarnHook(func(ctx context.Context, name, severity string) {
		receipt.EmitDLPWarning(ctx, e, receipt.EmitOpts{
			ActionID: receipt.NewActionID(), Target: "fixture", Transport: transportMCPStdio,
			Verdict: config.ActionWarn, Layer: "dlp", Pattern: name, Severity: severity,
		}, func(err error) { t.Errorf("emit native warning: %v", err) })
	})
	return sc, strings.Join(markers, " ")
}

func assertMCPNativeRecordBudget(t *testing.T, unit string, records, reserved int) {
	t.Helper()
	if records > reserved {
		t.Fatalf("%s: wrote %d native records, reserved %d", unit, records, reserved)
	}
	t.Logf("%s: wrote %d native records, reserved %d", unit, records, reserved)
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
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(8*time.Second))
	defer cancel()
	sc, fixtureInput := nativeMCPFindingScanner(t, e)
	const finding = "fixture reply finding"
	call := makeRequest(1, methodToolsCall, map[string]any{
		"name": "echo", "arguments": map[string]string{"prompt": fixtureInput},
	})
	reply := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":%q}]}}`, finding)
	if method == http.MethodGet {
		reply = fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/message","params":{"content":%q}}`, finding)
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
		Scanner: sc, Transport: "mcp_http",
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
	records := verifyMCPNativeClose(t, e, dir)
	entries, err := recorder.QuerySession(dir, e.Session(), &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	findings, terminal, outcomes := 0, 0, 0
	for _, entry := range entries.Entries {
		signed, err := receipt.Unmarshal(entry.RawDetail)
		if err != nil {
			t.Fatal(err)
		}
		record := signed.ActionRecord
		if record.Layer == "mcp_response_scan" && record.Pattern == finding {
			findings++
		}
		if strings.Contains(record.Pattern, "reason=native_ael_capacity") {
			if err := receipt.VerifyWithKey(signed, e.SignerKeyHex()); err != nil {
				t.Fatal(err)
			}
			terminal++
		} else if record.DecisionPhase == receipt.DecisionPhaseOutcome {
			outcomes++
		}
	}
	if findings != 1 || terminal != 1 {
		t.Fatalf("%s SSE exchange: finding receipts=%d terminal receipts=%d, want one each", method, findings, terminal)
	}
	if method == http.MethodGet {
		assertMCPNativeRecordBudget(t, "MCP SSE event", findings, nativeMCPEventRecords)
		assertMCPNativeRecordBudget(t, "MCP SSE subscription", records-findings, nativeMCPRequestRecords)
	} else {
		if outcomes != 1 || records != receipt.DLPWarningSlots+4 {
			t.Fatalf("MCP HTTP POST: wrote %d native records and %d outcomes, want warning overflow, finding, intent and outcome", records, outcomes)
		}
		assertMCPNativeRecordBudget(t, "MCP HTTP POST", records, nativeMCPRequestRecords)
	}
}

func TestDeferredNativeReservationSettlesAtCapacity(t *testing.T) {
	e, dir := newNativeMCPEmitter(t, nativeMCPRequestRecords+4)
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
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
	records := verifyMCPNativeClose(t, e, dir)
	if records != 1 {
		t.Fatalf("deferred cancel: wrote %d native records, want 1", records)
	}
	assertMCPNativeRecordBudget(t, "deferred cancel", records, nativeMCPPendingRecords)
}

func TestNativeCapacityRefusesMCPBridgesBeforeUpstream(t *testing.T) {
	e, dir := newNativeMCPEmitter(t, nativeMCPRequestRecords+4)
	if _, err := e.ReserveNativeRecords(2 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("capacity admission = %v", err)
	}
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	opts := MCPProxyOpts{Scanner: testInputScanner(t), ReceiptEmitter: e, RequireReceipts: true}
	const request = `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	const notification = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	for _, input := range []string{request, notification} {
		var out bytes.Buffer
		if err := RunHTTPProxy(t.Context(), strings.NewReader(input+"\n"), &out, io.Discard, upstream.URL, nil, opts); !errors.Is(err, ael.ErrCapacity) {
			t.Fatalf("POST bridge capacity result = %v", err)
		}
		if wantsReply := input == request; strings.Contains(out.String(), ael.ErrCapacity.Error()) != wantsReply {
			t.Fatalf("POST capacity reply = %q", out.String())
		}
	}
	reader, writer := io.Pipe()
	_ = reader.Close()
	defer func() { _ = writer.Close() }()
	var logs bytes.Buffer
	if err := RunHTTPProxy(t.Context(), strings.NewReader(request+"\n"), writer, &logs, upstream.URL, nil, opts); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("capacity result with closed stdout = %v", err)
	}
	if !strings.Contains(logs.String(), "write capacity refusal") {
		t.Fatalf("missing stdout error: %s", logs.String())
	}
	streamErr, setupErr := scanGETStream(t.Context(), transport.NewHTTPClient(upstream.URL, nil), transport.NewStdioWriter(io.Discard), io.Discard, opts, NewRequestTracker())
	if streamErr != nil || !errors.Is(setupErr, ael.ErrCapacity) {
		t.Fatalf("GET capacity result = %v, %v", streamErr, setupErr)
	}
	if err := RunWSProxy(t.Context(), strings.NewReader(request), io.Discard, io.Discard, wsURL(upstream), opts); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("WebSocket bridge capacity result = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("refused bridges reached upstream %d times", hits.Load())
	}
	verifyMCPNativeClose(t, e, dir)
}

func TestNativeCapacityTrackedRequestsKeepTheirOwnReservation(t *testing.T) {
	const request = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
	const trackingRefusal = "could not reserve a pending receipt outcome for this request ID"
	for _, mode := range []string{"stdio", "best_effort_stdio", "http", "websocket"} {
		t.Run(mode, func(t *testing.T) {
			e, dir := newNativeMCPEmitter(t, 4*nativeMCPRequestRecords)
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(8*time.Second))
			defer cancel()
			opts := MCPProxyOpts{Scanner: testInputScanner(t), Transport: transportMCPStdio, ReceiptEmitter: e, RequireReceipts: mode != "best_effort_stdio"}
			input := request + "\n" + request + "\n"
			switch mode {
			case "stdio", "best_effort_stdio":
				var out bytes.Buffer
				blocked := make(chan BlockedRequest, 2)
				tracker := NewRequestTracker()
				ForwardScannedInput(transport.NewStdioReader(strings.NewReader(input)), transport.NewStdioWriter(&out), io.Discard, config.ActionWarn, config.ActionBlock, blocked, nil, tracker, opts)
				if got := strings.Count(out.String(), request); got != 1 {
					t.Fatalf("duplicate stdio request reached upstream, count = %d", got)
				}
				refusal, ok := <-blocked
				if !ok || !strings.Contains(refusal.ErrorMessage, trackingRefusal) {
					t.Fatalf("duplicate stdio refusal = %+v", refusal)
				}
				emitPendingIncompleteOutcomes(io.Discard, tracker, opts, "test_complete")
			case "http":
				var hits atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					hits.Add(1)
					w.WriteHeader(http.StatusAccepted)
				}))
				defer upstream.Close()
				var out bytes.Buffer
				if err := RunHTTPProxy(ctx, strings.NewReader(input), &out, io.Discard, upstream.URL, nil, opts); err != nil {
					t.Fatal(err)
				}
				if hits.Load() != 1 || !strings.Contains(out.String(), trackingRefusal) {
					t.Fatalf("duplicate HTTP request: upstream hits=%d output=%s", hits.Load(), out.String())
				}
			case "websocket":
				upstream, frames := wsDrainServer(t)
				defer upstream.Close()
				reader, writer := io.Pipe()
				defer func() { _ = writer.Close() }()
				var out lockedHTTPBuffer
				done := make(chan error, 1)
				go func() { done <- RunWSProxy(ctx, reader, &out, io.Discard, wsURL(upstream), opts) }()
				if _, err := io.WriteString(writer, input); err != nil {
					t.Fatal(err)
				}
				testwait.For(t, time.Second, func() bool { return out.contains(trackingRefusal) && frames.Load() == 1 }, "duplicate WebSocket refusal")
				_ = writer.Close()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if frames.Load() != 1 {
					t.Fatalf("duplicate frame reached upstream, count = %d", frames.Load())
				}
			}
			if _, err := e.ReserveNativeRecords(5 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
				t.Fatalf("capacity admission = %v", err)
			}
			verifyMCPNativeClose(t, e, dir)
		})
	}
}

func TestHTTPListenerCapacitySettlesIntentBeforeUpstreamHeaders(t *testing.T) {
	e, dir := newNativeMCPEmitter(t, nativeMCPRequestRecords+4)
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(4*time.Second))
	defer cancel()
	entered, canceled := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		close(entered)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-ctx.Done():
		}
	}))
	defer upstream.Close()
	opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), ReceiptEmitter: e, RequireReceipts: true, ListenerShutdownTimeout: 50 * time.Millisecond}
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/", strings.NewReader(cleanToolsCallRequest))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	result := make(chan error, 1)
	go func() {
		response, err := upstream.Client().Do(req)
		if err == nil {
			if closeErr := response.Body.Close(); closeErr != nil {
				err = closeErr
			} else if response.StatusCode != http.StatusBadGateway {
				err = fmt.Errorf("status = %d, want %d", response.StatusCode, http.StatusBadGateway)
			}
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("admitted request did not reach upstream")
	}
	if _, err := e.ReserveNativeRecords(2 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("stop = %v, want %v", err, ael.ErrCapacity)
	}
	select {
	case <-canceled:
	case <-ctx.Done():
		t.Fatal("upstream headers wait was not canceled")
	}
	select {
	case err := <-result:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("client result = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("client did not return")
	}
	select {
	case <-e.NativeCapacity().Drained():
	case <-ctx.Done():
		t.Fatal("native admissions did not drain")
	}
	var intent, outcome receipt.ActionRecord
	entries, err := recorder.QuerySession(dir, e.Session(), &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries.Entries {
		signed, err := receipt.Unmarshal(entry.RawDetail)
		if err != nil {
			t.Fatal(err)
		}
		switch signed.ActionRecord.DecisionPhase {
		case receipt.DecisionPhaseIntent:
			intent = signed.ActionRecord
		case receipt.DecisionPhaseOutcome:
			outcome = signed.ActionRecord
		}
	}
	if intent.ActionID == "" || outcome.ActionID != intent.ActionID || !strings.Contains(outcome.Pattern, "reason="+nativeCapacityReason) {
		t.Fatalf("upstream cutoff intent=%q outcome=%q pattern=%q", intent.ActionID, outcome.ActionID, outcome.Pattern)
	}
	verifyMCPNativeClose(t, e, dir)
}

type observedNativeOutput struct {
	*io.PipeWriter
	writes chan string
}

func (w observedNativeOutput) Write(p []byte) (int, error) {
	w.writes <- string(p)
	return w.PipeWriter.Write(p)
}

func TestHTTPBridgeNativeCapacityCutsOffBlockedOutput(t *testing.T) {
	const event = `{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"subscription event"}}`
	for _, mode := range []string{"post", "deferred", "get"} {
		t.Run(mode, func(t *testing.T) {
			e, dir := newNativeMCPEmitter(t, 3*nativeMCPRequestRecords+4)
			opts := nativeDeferredOptions(t, e)
			opts.Transport = deferred.SurfaceMCPHTTPUpstream
			request := cleanToolsCallRequest
			if mode == "deferred" {
				request = heldNativeCall
			}

			received := make(chan string, 1)
			getCanceled := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "get" {
					switch r.Method {
					case http.MethodPost:
						w.Header().Set("Mcp-Session-Id", "fixture-session")
					case http.MethodGet:
						w.Header().Set("Content-Type", "text/event-stream")
						if _, err := io.WriteString(w, "data: "+event+"\n\n"); err != nil {
							t.Error(err)
							return
						}
						if err := http.NewResponseController(w).Flush(); err != nil {
							t.Error(err)
							return
						}
						<-r.Context().Done()
						close(getCanceled)
						return
					case http.MethodDelete:
						w.WriteHeader(http.StatusNoContent)
						return
					}
				}
				if r.Method != http.MethodPost {
					t.Errorf("unexpected upstream method %s", r.Method)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				received <- string(body)
				w.Header().Set("Content-Type", "application/json")
				if _, err := io.WriteString(w, heldNativeReply); err != nil {
					t.Error(err)
				}
			}))
			defer upstream.Close()

			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(2*time.Second))
			defer cancel()
			input, client := io.Pipe()
			defer func() { _ = client.Close() }()
			clientRead, clientWrite := io.Pipe()
			defer func() { _ = clientRead.Close() }()
			writes := make(chan string, 4)
			done := make(chan error, 1)
			go func() {
				done <- RunHTTPProxy(ctx, input, observedNativeOutput{clientWrite, writes}, io.Discard, upstream.URL, nil, opts)
			}()
			if _, err := io.WriteString(client, request+"\n"); err != nil {
				t.Fatal(err)
			}
			if mode == "deferred" {
				resolveNativeDeferredCall(t, opts.DeferManager)
			}
			select {
			case body := <-received:
				if body != request {
					t.Fatalf("upstream body = %q, want %q", body, request)
				}
			case <-ctx.Done():
				t.Fatal("call did not reach upstream")
			}
			wantBlocked := heldNativeReply
			if mode == "get" {
				select {
				case <-writes:
				case <-ctx.Done():
					t.Fatal("POST reply did not reach the downstream pipe")
				}
				reader := transport.NewStdioReader(clientRead)
				if reply, err := reader.ReadMessage(); err != nil || string(reply) != heldNativeReply {
					t.Fatalf("POST reply = %s, %v", reply, err)
				}
				wantBlocked = event
			}
			select {
			case reply := <-writes:
				if strings.TrimSpace(reply) != wantBlocked {
					t.Fatalf("attempted reply = %q", reply)
				}
			case <-ctx.Done():
				t.Fatal("reply did not reach the downstream pipe")
			}

			stoppedAt := time.Now()
			if _, err := e.ReserveNativeRecords(5 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
				t.Fatalf("capacity stop = %v, want %v", err, ael.ErrCapacity)
			}
			select {
			case err := <-done:
				if !errors.Is(err, ael.ErrCapacity) || time.Since(stoppedAt) < opts.ListenerShutdownTimeout {
					t.Fatalf("bridge exit = %v after %v", err, time.Since(stoppedAt))
				}
			case <-ctx.Done():
				t.Fatal("HTTP bridge remained blocked writing to the downstream pipe")
			}
			if _, err := clientRead.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("downstream after cutoff = %v, want EOF", err)
			}
			if mode == "get" {
				select {
				case <-getCanceled:
				case <-ctx.Done():
					t.Fatal("cutoff did not cancel the upstream GET")
				}
			}
			verifyMCPNativeClose(t, e, dir)
			if mode == "post" {
				assertNativeMCPOutcome(t, e, dir, "status=incomplete bytes=unknown reason=downstream_write_failed")
			}
		})
	}
}

func TestStdioNativeCapacityRecordsUndeliveredOutcome(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("shell subprocess test requires unix")
	}
	const received = `{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"request received"}}`
	const child = `
IFS= read -r request || exit 2
case "$request" in *'"id":1'*) ;; *) exit 3;; esac
printf '%s\n' "$1"
`
	for _, mode := range []string{"subprocess", "sandboxed"} {
		for _, state := range []string{"pending", "blocked"} {
			t.Run(mode+"/"+state, func(t *testing.T) {
				e, dir := newNativeMCPEmitter(t, 2*nativeMCPRequestRecords+4)
				ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(2*time.Second))
				defer cancel()
				input, client := io.Pipe()
				defer func() { _ = client.Close() }()
				clientRead, clientWrite := io.Pipe()
				defer func() { _ = clientRead.Close() }()
				writes := make(chan string, 4)
				output := observedNativeOutput{clientWrite, writes}
				opts := MCPProxyOpts{
					Scanner: testInputScanner(t), ReceiptEmitter: e, RequireReceipts: true,
					ListenerShutdownTimeout: 50 * time.Millisecond,
				}
				done := make(chan error, 1)
				script := child
				if state == "blocked" {
					script += `printf '%s
' "$2"` + "\n"
				}
				script += "exec sleep 30\n"
				go func() {
					args := []string{"sh", "-c", script, "sh", received, heldNativeReply}
					if mode == "sandboxed" {
						cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec // fixed test command
						done <- RunProxyWithSandbox(ctx, cmd, input, output, io.Discard, opts)
						return
					}
					done <- RunProxy(ctx, input, output, io.Discard, args, opts)
				}()
				if _, err := io.WriteString(client, cleanToolsCallRequest+"\n"); err != nil {
					t.Fatal(err)
				}
				select {
				case <-writes:
				case <-ctx.Done():
					t.Fatal("child did not acknowledge the request")
				}
				clientMessages := transport.NewStdioReader(clientRead)
				if got, err := clientMessages.ReadMessage(); err != nil || string(got) != received {
					t.Fatalf("child acknowledgment = %s, %v", got, err)
				}
				if state == "blocked" {
					select {
					case got := <-writes:
						if strings.TrimSpace(got) != heldNativeReply {
							t.Fatalf("attempted reply = %q", got)
						}
					case <-ctx.Done():
						t.Fatal("reply did not reach the downstream pipe")
					}
				}
				if _, err := e.ReserveNativeRecords(3 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
					t.Fatalf("capacity stop = %v, want %v", err, ael.ErrCapacity)
				}
				select {
				case err := <-done:
					if !errors.Is(err, ael.ErrCapacity) {
						t.Fatalf("proxy exit = %v, want %v", err, ael.ErrCapacity)
					}
				case <-ctx.Done():
					t.Fatal("proxy did not stop at capacity cutoff")
				}
				if _, err := clientMessages.ReadMessage(); !errors.Is(err, io.EOF) {
					t.Fatalf("downstream after cutoff = %v, want EOF", err)
				}
				verifyMCPNativeClose(t, e, dir)
				want := "status=incomplete bytes=unknown reason=" + nativeCapacityReason
				if state == "blocked" {
					want = "status=incomplete bytes=unknown reason=downstream_write_failed"
				}
				assertNativeMCPOutcome(t, e, dir, want)
			})
		}
	}
}

func assertNativeMCPOutcome(t *testing.T, e *receipt.Emitter, dir, want string) {
	t.Helper()
	entries, err := recorder.QuerySession(dir, e.Session(), &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	var intentID string
	var outcomes []receipt.ActionRecord
	for _, entry := range entries.Entries {
		signed, err := receipt.Unmarshal(entry.RawDetail)
		if err != nil {
			t.Fatal(err)
		}
		record := signed.ActionRecord
		if record.DecisionPhase == receipt.DecisionPhaseIntent {
			intentID = record.ActionID
		}
		if record.DecisionPhase == receipt.DecisionPhaseOutcome {
			outcomes = append(outcomes, record)
		}
	}
	if intentID == "" || len(outcomes) != 1 || outcomes[0].ActionID != intentID || !strings.Contains(outcomes[0].Pattern, want) {
		var patterns []string
		for _, outcome := range outcomes {
			patterns = append(patterns, outcome.Pattern)
		}
		t.Fatalf("tools/call terminal outcomes = %q, want one paired outcome containing %q", patterns, want)
	}
}
