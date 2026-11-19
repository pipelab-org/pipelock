// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const settlementEndpointEnv = "PIPELOCK_TEST_SETTLEMENT_ENDPOINT"

func TestMCPSettlementStdioEndpoint(t *testing.T) {
	dir := os.Getenv(settlementEndpointEnv)
	if dir == "" {
		return
	}

	faultNumber, err := strconv.ParseUint(os.Getenv("PIPELOCK_TEST_SETTLEMENT_FAULT"), 10, 8)
	if err != nil {
		t.Fatal(err)
	}
	fault := settlementFault(faultNumber)
	// The testing harness writes PASS to stdout, which is the protocol pipe.
	// Close it after the endpoint has finished emitting protocol messages.
	defer func() { _ = os.Stdout.Close() }()
	if fault == settlementWriteUpstream {
		if err := os.Stdin.Close(); err != nil {
			t.Fatal(err)
		}
		markSettlementFixtureFault(t, dir)
	}
	if err := os.WriteFile(filepath.Join(dir, settlementReady), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if fault == settlementWriteUpstream {
		testwait.For(t, settlementBound, func() bool {
			_, err := os.Stat(filepath.Join(dir, settlementStop))
			return err == nil
		}, "endpoint exit signal")
		return
	}

	reader := transport.NewStdioReader(os.Stdin)
	raw, err := readSettlementStdio(t, dir, reader)
	if errors.Is(err, io.EOF) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	tool := settlementToolName(raw)
	if err := recordSettlementSend(dir, tool); err != nil {
		t.Fatal(err)
	}
	if tool == methodNotificationsInitialized {
		return
	}
	switch fault {
	case settlementReadEmpty:
		markSettlementFixtureFault(t, dir)
		return
	case settlementReadPartial:
		markSettlementFixtureFault(t, dir)
		_, _ = io.WriteString(os.Stdout, "{\"jsonrpc\"")
		return
	case settlementTimeout, settlementClientCancel, settlementShutdown:
		_, _ = readSettlementStdio(t, dir, reader)
		return
	case settlementDuplicate:
		second, err := readSettlementStdio(t, dir, reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := recordSettlementSend(dir, settlementToolName(second)); err != nil {
			t.Fatal(err)
		}
	}
	reply := settlementReply
	if fault == settlementScanError {
		markSettlementFixtureFault(t, dir)
		reply = malformedSettlementReply(reply)
	} else if err := appendSettlementObservation(dir, settlementResponses, tool); err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintln(os.Stdout, reply)
}

func readSettlementStdio(t *testing.T, dir string, reader *transport.StdioReader) ([]byte, error) {
	t.Helper()
	raw, err := reader.ReadMessage()
	if err == nil {
		synced, syncErr := settlementObserved(dir, settlementSynced)
		if syncErr != nil {
			t.Fatal(syncErr)
		}
		if logErr := recordSettlementWire(dir, settlementWireRPC("stdio", raw, synced)); logErr != nil {
			t.Fatal(logErr)
		}
	}
	return raw, err
}

func markSettlementFixtureFault(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, settlementFaultMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func malformedSettlementReply(reply string) string {
	// Substituting a malformed version can still parse as JSON, but it must
	// fail response inspection while retaining the ID for settlement.
	return strings.Replace(reply, "\"jsonrpc\":\"2.0\"", "\"jsonrpc\":[]", 1)
}

func (p *settlementProbe) awaitSend(t *testing.T, ctx context.Context) {
	t.Helper()
	if p.cell.transport != settlementStdio {
		select {
		case <-p.send:
		case <-ctx.Done():
			t.Fatal("upstream did not receive the request")
		}
		return
	}
	testwait.For(t, settlementBound/2, func() bool {
		sends, _ := settlementObserved(p.dir, settlementObservations)
		return len(sends) != 0
	}, "subprocess received the request")
}

func (p *settlementProbe) armReadDeadline(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case conn := <-p.dialed:
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for the upstream connection")
	}
}

func (p *settlementProbe) runStdio(t *testing.T, ctx context.Context, cancel context.CancelFunc, opts MCPProxyOpts) {
	t.Helper()
	input, feed := io.Pipe()
	t.Cleanup(func() { _ = feed.Close() })
	out := settlementOutput{p: p, written: make(chan struct{}, 2)}
	var logs syncBuffer
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	done := make(chan error, 1)

	startRead := make(chan struct{})
	started, finished := false, false
	startProxy := func(run func() error) {
		started = true
		go func() {
			err := run()
			_ = input.CloseWithError(err)
			done <- err
		}()
	}
	defer func() {
		if !started || finished {
			return
		}
		cancel()
		_ = feed.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Logf("proxy exited during cleanup: %v", err)
			}
		case <-time.After(settlementBound):
			t.Error("transport did not exit after cancellation")
		}
	}()
	writeInput := func(call string) {
		stop := context.AfterFunc(ctx, func() { _ = feed.CloseWithError(ctx.Err()) })
		defer stop()
		if _, err := io.WriteString(feed, call); err != nil {
			t.Fatalf("write fixture input: %v", err)
		}
	}
	switch p.cell.transport {
	case settlementStdio:
		if p.cell.fault == settlementTimeout {
			opts.outputForwardStartedForTest = func() {
				select {
				case <-startRead:
				case <-ctx.Done():
				}
			}
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := []string{executable, "-test.run=^TestMCPSettlementStdioEndpoint$"}
		if p.cell.fault == settlementDial {
			command = []string{filepath.Join(p.dir, "missing-program")}
			p.fault.Add(1)
		}
		startProxy(func() error {
			return RunProxy(ctx, input, out, &logs, command, opts,
				settlementEndpointEnv+"="+p.dir, "PIPELOCK_TEST_SETTLEMENT_FAULT="+strconv.Itoa(int(p.cell.fault)),
				"GORACE=atexit_sleep_ms=0")
		})
		if p.cell.fault == settlementWriteUpstream {
			testwait.For(t, settlementBound/2, func() bool {
				_, err := os.Stat(filepath.Join(p.dir, settlementReady))
				return err == nil
			}, "subprocess closed its request pipe")
		}
	case settlementWebSocket:
		url := p.wsUpstream(t)
		if p.cell.fault == settlementDial {
			opts.AuthorityVerifier = allowAuthorityVerifier(nil)
			opts.AuthorityActor = "operator"
			opts.AuthorityDestination = url
		}
		startProxy(func() error { return RunWSProxy(ctx, input, out, &logs, url, opts) })
		switch p.cell.fault {
		case settlementDial:
		case settlementUpgradeAppend:
			select {
			case err := <-done:
				finished = true
				if err == nil || !strings.Contains(err.Error(), "recording upstream WebSocket admission") {
					t.Fatalf("expected WebSocket admission recording error, got %v", err)
				}
				return
			case <-p.upgraded:
				t.Error("WebSocket upgraded with no admission")
				return
			case <-ctx.Done():
				t.Fatal("WebSocket did not refuse an unwritable admission")
			}
		default:
			select {
			case <-p.upgraded:
			case <-ctx.Done():
				t.Fatal("upstream did not complete upgrade")
			}
		}
	case settlementBridgeJSON, settlementBridgeSSE:
		url := p.httpUpstream(t)
		startProxy(func() error { return RunHTTPProxy(ctx, input, out, &logs, url, nil, opts) })
	default:
		t.Fatal("stdio driver missing transport")
	}

	if !p.cell.subprocessStartFailure() {
		call := deferKillTestCall
		if p.cell.pairedNotification() {
			call = strings.Replace(call, `"id":1,`, "", 1)
		} else if p.cell.notification {
			call = settlementHandshake + "\n"
		}
		if p.cell.transport == settlementWebSocket && p.cell.fault == settlementDial {
			call = strings.Replace(call, "\"arguments\":{}", "\"arguments\":{},\"_meta\":{\"com.pipelock/authority\":\"grant\"}", 1)
		}
		writeInput(call)
	}
	var resolved <-chan error
	if p.cell.deferred && !p.cell.subprocessStartFailure() {
		var hold deferred.HeldAction
		testwait.For(t, settlementBound/2, func() bool {
			holds := opts.DeferManager.Snapshot()
			if len(holds) != 1 {
				return false
			}
			hold = holds[0]
			return true
		}, "held call")
		if p.cell.transport == settlementStdio {
			if err := opts.DeferManager.Resolve(hold.DeferID, config.ActionAllow, deferred.SourceApproval); err != nil {
				t.Fatal(err)
			}
		} else {
			resolution := make(chan error, 1)
			resolved = resolution
			go func() {
				resolution <- opts.DeferManager.Resolve(hold.DeferID, config.ActionAllow, deferred.SourceApproval)
			}()
		}
	}
	if p.cell.fault == settlementDuplicate {
		p.awaitSend(t, ctx)
		writeInput(strings.Replace(deferKillTestCall, settlementTool, settlementOtherTool, 1))
		p.fault.Add(1)
	}
	if p.holdResponse() {
		p.awaitSend(t, ctx)
		switch p.cell.fault {
		case settlementTimeout:
			switch p.cell.transport {
			case settlementStdio:
				close(startRead)
			case settlementWebSocket:
				p.armReadDeadline(t, ctx)
			}
		case settlementClientCancel:
			_ = feed.Close()
			p.fault.Add(1)
		case settlementShutdown:
			cancel()
			p.fault.Add(1)
		}
	} else if p.cell.transport == settlementStdio && p.cell.fault == settlementWriteUpstream {
		// Closing the client pipe gives the input loop a deterministic exit
		// after trying the already-closed subprocess stdin.
		_ = feed.Close()
		if err := os.WriteFile(filepath.Join(p.dir, settlementStop), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	} else if p.cell.fault == settlementIntentAppend && (p.cell.required || p.cell.deferred) {
		select {
		case <-out.written:
			_ = feed.Close()
		case err := <-done:
			finished = true
			if err != nil {
				t.Logf("proxy exited after admission failure: %v", err)
			}
			return
		case <-ctx.Done():
			t.Fatal("no client refusal after admission append failed")
		}
	}
	if p.cell.bridgeLifecycle() {
		// Observe the POST result and both subscription notifications. The
		// last stream stays open until stdin EOF triggers session cleanup.
		for range 3 {
			select {
			case <-out.written:
			case <-ctx.Done():
				t.Fatal("bridge did not complete its subscription reconnect")
			}
		}
	}
	if resolved != nil {
		select {
		case err := <-resolved:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(settlementBound):
			t.Fatal("release did not finish")
		}
	}
	if p.cell.transport != settlementWebSocket &&
		(p.cell.fault != settlementTimeout || p.cell.transport != settlementStdio) {
		_ = feed.Close()
	}
	select {
	case err := <-done:
		finished = true
		if p.cell.pairedNotification() && len(out.written) != 0 {
			t.Error("notification unexpectedly received a response")
		}
		if err != nil {
			t.Logf("proxy exited: %v", err)
		}
		if p.cell.transport == settlementStdio && p.cell.fault == settlementWriteUpstream {
			if !strings.Contains(logs.String(), "input forward error") {
				t.Error("subprocess did not report the failed send")
			}
			p.observeSendFailure(t, "stdio")
		}
		if p.cell.fault == settlementTimeout && strings.Contains(logs.String(), "timeout") {
			p.fault.Add(1)
		}
	case <-time.After(settlementBound):
		t.Fatal("transport did not finish before the teardown deadline")
	}
}

type settlementListener struct {
	net.Listener
	stopped chan struct{}
}

func (l settlementListener) Close() error {
	err := l.Listener.Close()
	if err == nil {
		close(l.stopped)
	}
	return err
}

func (p *settlementProbe) runListener(t *testing.T, ctx context.Context, cancel context.CancelFunc, opts MCPProxyOpts) {
	t.Helper()
	upstream := p.httpUpstream(t)
	listener := newListenerProxyTestListener(t)
	wrapped := &headerFailListener{Listener: listener, failed: make(chan struct{})}
	done := make(chan error, 1)
	var logs syncBuffer
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	handlerCancel := make(chan context.CancelFunc, 1)
	if p.cell.fault == settlementRequestCancel {
		opts.ListenerPrincipalResolver = func(r *http.Request) (ListenerPrincipal, error) {
			handlerCtx, cancelHandler := context.WithCancel(r.Context())
			t.Cleanup(cancelHandler)
			*r = *r.WithContext(handlerCtx)
			handlerCancel <- cancelHandler
			return ListenerPrincipal{}, nil
		}
	}
	acceptClosed := make(chan struct{})
	go func() {
		done <- RunHTTPListenerProxy(ctx, settlementListener{Listener: wrapped, stopped: acceptClosed}, upstream, &logs, opts)
	}()
	stop := sync.OnceFunc(func() {
		cancel()
		listener.closeConnections()
		select {
		case err := <-done:
			if err != nil {
				t.Logf("HTTP listener exited: %v", err)
			}
		case <-time.After(settlementBound):
			t.Error("HTTP listener did not stop")
		}
	})
	defer stop()

	url := "http://" + listener.Addr().String()
	waitForHTTPHealth(t, url)
	if p.cell.fault == settlementWriteClient {
		wrapped.fail.Store(true)
	}
	requestCtx, cancelRequest := context.WithTimeout(t.Context(), settlementBound)
	defer cancelRequest()
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	send := func(body string) {
		var request *http.Request
		var err error
		if method := p.cell.listenerMethod(); method != http.MethodPost {
			request, err = http.NewRequestWithContext(requestCtx, method, url+"/", nil)
		} else {
			request, err = http.NewRequestWithContext(requestCtx, http.MethodPost, url+"/", strings.NewReader(body))
		}
		if err != nil {
			t.Error(err)
			return
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		response, err := client.Do(request)
		if err == nil {
			defer func() { _ = response.Body.Close() }()
			_, _ = io.Copy(io.Discard, response.Body)
		}
	}

	// Concurrent listener requests each have an independent correlation set.
	// The second receives no reply from upstream.
	var requests sync.WaitGroup
	call := deferKillTestCall
	if p.cell.notification {
		call = settlementHandshake
	}
	requests.Go(func() { send(call) })
	if p.cell.fault == settlementDuplicate {
		p.awaitSend(t, ctx)
		requests.Go(func() { send(strings.Replace(deferKillTestCall, settlementTool, settlementOtherTool, 1)) })
		p.awaitSend(t, ctx)
		p.stopWaiting()
		p.fault.Add(1)
	} else if p.holdResponse() {
		p.awaitSend(t, ctx)
		switch p.cell.fault {
		case settlementTimeout:
			p.armReadDeadline(t, ctx)
		case settlementClientCancel:
			cancelRequest()
			p.fault.Add(1)
		case settlementRequestCancel:
			select {
			case cancelHandler := <-handlerCancel:
				cancelHandler()
				p.fault.Add(1)
			case <-requestCtx.Done():
				t.Fatal("request context fault was not armed")
			}
		case settlementShutdown:
			cancel()
			select {
			case <-acceptClosed:
				p.stopWaiting()
				p.fault.Add(1)
			case <-requestCtx.Done():
				t.Fatal("listener did not start draining")
			}
		}
	}
	requests.Wait()
	stop()
	if p.cell.fault == settlementTimeout && strings.Contains(logs.String(), "timeout") {
		p.fault.Add(1)
	}
	if p.cell.fault == settlementWriteClient {
		select {
		case <-wrapped.failed:
			p.fault.Add(1)
		default:
		}
	}
}
