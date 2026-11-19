// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestV3HTTPTransportIntentPrecedesUpstreamSend(t *testing.T) {
	for _, transport := range []string{"fetch", "forward"} {
		for _, closed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/closed=%t", transport, closed), func(t *testing.T) {
				p, writer, dir, keys := newTestV3HTTPProxy(t, transport)
				if closed {
					if err := writer.Close(t.Context(), nil); err != nil {
						t.Fatal(err)
					}
				}
				var hits atomic.Int64
				var before atomic.Bool
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					result, verifyErr := v3.VerifyPaths(r.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
					if verifyErr == nil && result.Integrity == "ok" && result.Counts.EffectsUnknown != nil &&
						*result.Counts.EffectsUnknown == 1 {
						before.Store(true)
					}
					_, _ = w.Write([]byte("example"))
				}))
				t.Cleanup(upstream.Close)
				response := httptest.NewRecorder()
				if transport == "fetch" {
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil)
					p.handleFetch(response, req)
				} else {
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
					p.handleForwardHTTP(response, req)
				}
				if closed {
					if hits.Load() != 0 || response.Code != http.StatusForbidden ||
						response.Header().Get(blockreason.HeaderReason) != string(blockreason.ReceiptEmissionFailed) {
						t.Fatalf("failed receipt reached upstream or wrong response: hits=%d code=%d body=%s", hits.Load(), response.Code, response.Body)
					}
					return
				}
				if hits.Load() != 1 || !before.Load() || response.Code != http.StatusOK {
					t.Fatalf("upstream effect lacked its earlier intent: hits=%d prior=%t code=%d body=%s", hits.Load(), before.Load(), response.Code, response.Body)
				}
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
				if err != nil || result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil ||
					*result.Counts.EffectsCompleted != 1 {
					t.Fatalf("upstream outcome missing: %+v (%v)", result, err)
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".receipt-v3.jsonl") {
					t.Fatalf("unexpected receipt files under v3: %v", entries)
				}
			})
		}
	}
}

func newTestV3HTTPProxy(t *testing.T, surface string) (*Proxy, *v3.StreamWriter, string, []ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	keySeed := sha256.Sum256([]byte("receipt transport fixture"))
	key := ed25519.NewKeyFromSeed(keySeed[:])
	keys := []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}
	cfg := testScannerConfig()
	cfg.Internal = nil
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.MaxTunnelSeconds = 10
	cfg.ForwardProxy.IdleTimeoutSeconds = 2
	cfg.WebSocketProxy.Enabled = true
	cfg.WebSocketProxy.MaxConnectionSeconds = 10
	cfg.WebSocketProxy.IdleTimeoutSeconds = 2
	cfg.ResponseScanning.Enabled = false
	cfg.FlightRecorder.RequireReceipts = true
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
	t.Cleanup(func() { _ = writer.Close(t.Context(), nil) })
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), func(p *Proxy) { p.receiptV3 = writer })
	if err != nil {
		t.Fatal(err)
	}
	return p, writer, dir, keys
}

func TestV3ConnectIntentPrecedesTunnelDial(t *testing.T) {
	p, writer, dir, keys := newTestV3HTTPProxy(t, "connect")
	target, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	beforeEffect := make(chan bool, 1)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			beforeEffect <- false
			return
		}
		defer func() { _ = conn.Close() }()
		result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
		// The client may already have received 200 when the independently
		// scheduled accept handler runs. Either state proves the intent.
		beforeEffect <- err == nil && result.Integrity == "ok" && result.Counts.Decisions != nil &&
			len(*result.Counts.Decisions) == 1
	}()
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		p.handleConnect(w, r)
	}))
	t.Cleanup(server.Close)
	conn := dialProxy(t, strings.TrimPrefix(server.URL, "http://"))
	addr := target.Addr().String()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d, want 200", response.StatusCode)
	}
	assertTransportReceiptOrder(t, beforeEffect, done)
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
	if err != nil || result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil ||
		*result.Counts.EffectsCompleted != 1 {
		t.Fatalf("CONNECT completion missing: %+v (%v)", result, err)
	}
}

func TestV3WebSocketIntentPrecedesUpstreamHandshake(t *testing.T) {
	p, writer, dir, keys := newTestV3HTTPProxy(t, "websocket")
	beforeEffect := make(chan bool, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, verifyErr := v3.VerifyPaths(r.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
		beforeEffect <- verifyErr == nil && result.Integrity == "ok" && result.Counts.EffectsUnknown != nil &&
			*result.Counts.EffectsUnknown == 1
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(backend.Close)
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		p.handleWebSocket(w, r)
	}))
	t.Cleanup(server.Close)
	response := requestWSHandshake(t, strings.TrimPrefix(server.URL, "http://"), strings.TrimPrefix(backend.URL, "http://"), nil)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("WebSocket status=%d, want 101", response.StatusCode)
	}
	assertTransportReceiptOrder(t, beforeEffect, done)
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
	if err != nil || result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil ||
		*result.Counts.EffectsCompleted != 2 {
		t.Fatalf("WebSocket upstream and downstream handshake receipts missing: %+v (%v)", result, err)
	}
}

func assertTransportReceiptOrder(t *testing.T, observed <-chan bool, done <-chan struct{}) {
	t.Helper()
	timer := time.NewTimer(6 * time.Second)
	defer timer.Stop()
	select {
	case confirmed := <-observed:
		if !confirmed {
			t.Fatal("effect reached the endpoint without a verified earlier receipt")
		}
	case <-timer.C:
		t.Fatal("upstream did not observe the effect")
	}
	select {
	case <-done:
	case <-timer.C:
		t.Fatal("transport did not end")
	}
}
