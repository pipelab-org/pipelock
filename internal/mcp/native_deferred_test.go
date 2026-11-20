// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const (
	heldNativeCall  = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"prompt":"fixture hold marker"}}}`
	heldNativeReply = `{"jsonrpc":"2.0","id":1,"result":{}}`
)

func nativeDeferredOptions(t *testing.T, e *receipt.Emitter) MCPProxyOpts {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "fixture hold", Regex: "fixture hold marker"}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	manager := deferred.NewManager(deferred.Config{
		Enabled: true, Timeout: time.Minute, MaxPending: 2, MaxPendingPerSession: 2, MaxPendingBytes: 4096,
	})
	return MCPProxyOpts{
		Scanner: sc, ReceiptEmitter: e, RequireReceipts: true, DeferManager: manager,
		Transport: transportMCPStdio, ListenerShutdownTimeout: 50 * time.Millisecond,
		InputCfg: &InputScanConfig{Enabled: true, Action: config.ActionDefer, OnParseError: config.ActionBlock},
	}
}

func resolveNativeDeferredCall(t *testing.T, manager *deferred.Manager) <-chan error {
	t.Helper()
	testwait.For(t, time.Second, func() bool { return manager.HeldCount() == 1 }, "deferred call registered")
	held := manager.Snapshot()
	if len(held) != 1 {
		t.Fatalf("pending calls = %d, want 1", len(held))
	}
	done := make(chan error, 1)
	go func() { done <- manager.Resolve(held[0].DeferID, config.ActionAllow, deferred.SourceOperator) }()
	return done
}

func TestStdioNativeCapacitySettlesReleasedDeferredReply(t *testing.T) {
	e, dir := newNativeMCPEmitter(t, nativeMCPRequestRecords+4)
	opts := nativeDeferredOptions(t, e)
	opts.nativeStdio = true
	input, client := io.Pipe()
	defer func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	}()
	tracker := NewRequestTracker()
	blocked := make(chan BlockedRequest, 4)
	var sent lockedHTTPBuffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardScannedInput(transport.NewStdioReader(input), transport.NewStdioWriter(&sent), io.Discard,
			config.ActionDefer, config.ActionBlock, blocked, nil, tracker, opts)
	}()
	if _, err := io.WriteString(client, heldNativeCall+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-resolveNativeDeferredCall(t, opts.DeferManager):
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(testwait.Deadline(time.Second)):
		t.Fatal("resolution did not finish")
	}
	if !sent.contains(heldNativeCall) {
		t.Fatalf("released call not sent upstream: %s", sent.String())
	}
	if _, err := e.ReserveNativeRecords(2 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("stop = %v, want %v", err, ael.ErrCapacity)
	}
	var received bytes.Buffer
	if _, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(heldNativeReply)),
		transport.NewStdioWriter(&received), io.Discard, tracker, opts); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(received.String()); got != heldNativeReply {
		t.Fatalf("client reply = %q, want %q", got, heldNativeReply)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(testwait.Deadline(time.Second)):
		t.Fatal("input forwarding did not exit")
	}
	verifyMCPNativeClose(t, e, dir)
}

func TestHTTPBridgeCapacityCutsOffReleasedDeferredCall(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream bool
	}{{"headers", false}, {"stream", true}} {
		t.Run(tc.name, func(t *testing.T) {
			e, dir := newNativeMCPEmitter(t, 3*nativeMCPRequestRecords+4)
			opts := nativeDeferredOptions(t, e)
			opts.Transport = deferred.SurfaceMCPHTTPUpstream
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(4*time.Second))
			defer cancel()
			entered, canceled := make(chan struct{}), make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Errorf("read request: %v", err)
					return
				}
				if tc.stream {
					w.Header().Set("Content-Type", "text/event-stream")
					if err := http.NewResponseController(w).Flush(); err != nil {
						t.Errorf("flush headers: %v", err)
						return
					}
				}
				close(entered)
				select {
				case <-r.Context().Done():
					close(canceled)
				case <-ctx.Done():
				}
			}))
			defer upstream.Close()
			input, client := io.Pipe()
			defer func() {
				if err := client.Close(); err != nil {
					t.Error(err)
				}
			}()
			var out lockedHTTPBuffer
			done := make(chan error, 1)
			go func() { done <- RunHTTPProxy(ctx, input, &out, io.Discard, upstream.URL, nil, opts) }()
			if _, err := io.WriteString(client, heldNativeCall+"\n"); err != nil {
				t.Fatal(err)
			}
			resolved := resolveNativeDeferredCall(t, opts.DeferManager)
			select {
			case <-entered:
			case err := <-resolved:
				t.Fatalf("deferred resolution ended before sending: %v, output=%s", err, out.String())
			case <-ctx.Done():
				t.Fatal("released call did not reach upstream")
			}
			before, _ := e.HealthSnapshot()
			second := strings.Replace(cleanToolsCallRequest, `"id":1`, `"id":2`, 1)
			if _, err := io.WriteString(client, second+"\n"); err != nil {
				t.Fatal(err)
			}
			testwait.For(t, time.Second, func() bool {
				after, _ := e.HealthSnapshot()
				return after.ChainSeq > before.ChainSeq
			}, "second request signed before waiting for the upstream sender")
			if _, err := e.ReserveNativeRecords(5 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
				t.Fatalf("stop = %v, want %v", err, ael.ErrCapacity)
			}
			select {
			case <-canceled:
			case <-time.After(testwait.Deadline(time.Second)):
				t.Fatal("capacity cutoff did not cancel the released upstream call")
			}
			select {
			case err := <-resolved:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("resolution did not return")
			}
			select {
			case err := <-done:
				if !errors.Is(err, ael.ErrCapacity) {
					t.Fatalf("HTTP bridge exit = %v, want %v", err, ael.ErrCapacity)
				}
			case <-ctx.Done():
				t.Fatal("HTTP bridge did not stop")
			}
			verifyMCPNativeClose(t, e, dir)
		})
	}
}
