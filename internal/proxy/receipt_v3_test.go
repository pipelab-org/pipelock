// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestV3HTTPTransportIntentPrecedesUpstreamSend(t *testing.T) {
	for _, transport := range []string{"fetch", "forward", "reverse"} {
		for _, stage := range []string{"healthy", "before_send", "before_delivery", "advisory"} {
			t.Run(transport+"/"+stage, func(t *testing.T) {
				p, writer, dir, keys := newTestV3HTTPProxy(t, transport, stage != "advisory")
				if stage == "before_send" {
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
					if stage == "before_delivery" {
						if err := writer.Close(r.Context(), nil); err != nil {
							t.Error(err)
						}
					}
					_, _ = w.Write([]byte("example"))
				}))
				t.Cleanup(upstream.Close)
				var deliveredWithIntent bool
				onDelivery := func() {
					result, verifyErr := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
					deliveredWithIntent = verifyErr == nil && result.Integrity == "ok" &&
						result.Counts.EffectsCompleted != nil && result.Counts.EffectsUnknown != nil &&
						*result.Counts.EffectsUnknown >= 1 && *result.Counts.EffectsCompleted+*result.Counts.EffectsUnknown == 2
				}
				response := &v3ResponseRecorder{ResponseRecorder: httptest.NewRecorder(), onHeader: onDelivery}
				switch transport {
				case "fetch":
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil)
					p.handleFetch(response, req)
				case "forward":
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
					p.handleForwardHTTP(response, req)
				case "reverse":
					target, err := url.Parse(upstream.URL)
					if err != nil {
						t.Fatal(err)
					}
					reverse := NewReverseProxy(target, p.ConfigPtr(), p.ScannerPtr(), audit.NewNop(), metrics.New(), nil, nil, nil)
					reverse.SetOwnerProxy(p)
					reverse.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
				}
				if stage == "before_send" {
					if hits.Load() != 0 || response.Code != http.StatusForbidden ||
						response.Header().Get(blockreason.HeaderReason) != string(blockreason.ReceiptEmissionFailed) {
						t.Fatalf("failed receipt reached upstream or wrong response: hits=%d code=%d body=%s", hits.Load(), response.Code, response.Body)
					}
					return
				}
				if stage == "before_delivery" {
					if hits.Load() != 1 || response.Code != http.StatusForbidden ||
						response.Header().Get(blockreason.HeaderReason) != string(blockreason.ReceiptEmissionFailed) ||
						strings.Contains(response.Body.String(), "example") {
						t.Fatalf("unconfirmed response was delivered: hits=%d code=%d body=%s", hits.Load(), response.Code, response.Body)
					}
					return
				}
				if hits.Load() != 1 || !before.Load() || !deliveredWithIntent || response.Code != http.StatusOK {
					t.Fatalf("effect lacked its earlier intent: hits=%d upstream=%t downstream=%t code=%d body=%s", hits.Load(), before.Load(), deliveredWithIntent, response.Code, response.Body)
				}
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
				if err != nil || result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil ||
					*result.Counts.EffectsCompleted != 2 {
					t.Fatalf("two HTTP outcomes required: %+v (%v)", result, err)
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

type v3ResponseRecorder struct {
	*httptest.ResponseRecorder
	onHeader func()
}

func (w *v3ResponseRecorder) WriteHeader(code int) {
	if code == http.StatusOK {
		w.onHeader()
	}
	w.ResponseRecorder.WriteHeader(code)
}

func newTestV3HTTPProxy(t *testing.T, surface string, required bool) (*Proxy, *v3.StreamWriter, string, []ed25519.PublicKey) {
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
	cfg.FlightRecorder.RequireReceipts = required
	writer, err := v3.OpenStreamWriter(t.Context(), v3.StreamWriterOptions{
		Dir: dir, SigningKey: key, PolicyHash: v3.Digest(nil),
		Identity: v3.Writer{Instance: "example", Product: "Pipelock", Version: "3"},
		Coverage: v3.Coverage{
			ReceiptsRequired: required, Surfaces: []string{surface},
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
	p, writer, dir, keys := newTestV3HTTPProxy(t, "connect", true)
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
	p, writer, dir, keys := newTestV3HTTPProxy(t, "websocket", true)
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

func TestV3WebSocketPayloadWaitsForReceipt(t *testing.T) {
	for _, point := range []string{"open", "upstream", "downstream", "denied"} {
		t.Run(point, func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, "websocket", true)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			backendResult := make(chan error, 1)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, _, _, err := ws.UpgradeHTTP(r, w)
				if err != nil {
					backendResult <- err
					return
				}
				defer func() { _ = conn.Close() }()
				message, _, readErr := wsutil.ReadClientData(conn)
				if point == "upstream" || point == "denied" {
					if readErr == nil {
						backendResult <- fmt.Errorf("upstream received a refused payload")
					} else {
						backendResult <- nil
					}
					return
				}
				if readErr != nil {
					backendResult <- readErr
					return
				}
				if point == "downstream" {
					if err := writer.Close(ctx, nil); err != nil {
						backendResult <- err
						return
					}
				}
				backendResult <- wsutil.WriteServerMessage(conn, ws.OpText, message)
			}))
			t.Cleanup(backend.Close)
			done := make(chan struct{})
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				p.handleWebSocket(w, r)
			}))
			t.Cleanup(proxy.Close)
			target := "ws://" + strings.TrimPrefix(backend.URL, "http://")
			conn, err := wsTestDial(ctx, ws.Dialer{}, "ws://"+strings.TrimPrefix(proxy.URL, "http://")+"/ws?url="+url.QueryEscape(target))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if deadline, ok := ctx.Deadline(); ok {
				if err := conn.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
			}
			if point == "upstream" {
				if err := writer.Close(ctx, nil); err != nil {
					t.Fatal(err)
				}
			}
			const message = "ordinary message"
			opcode := ws.OpText
			if point == "denied" {
				opcode = ws.OpBinary
			}
			if err := wsutil.WriteClientMessage(conn, opcode, []byte(message)); err != nil {
				t.Fatal(err)
			}
			got, _, err := wsutil.ReadServerData(conn)
			if point == "open" {
				if err != nil || string(got) != message {
					t.Fatalf("client received %q (%v)", got, err)
				}
			} else if err == nil {
				t.Fatalf("client received a refused payload: %q", got)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-backendResult:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if point == "upstream" || point == "downstream" {
				return
			}
			if err := writer.Close(ctx, nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(ctx, []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil {
				t.Fatalf("WebSocket history failed verification: %+v (%v)", result, err)
			}
			if point == "denied" {
				if *result.Counts.EffectsCompleted != 2 || result.Counts.Decisions == nil ||
					!slices.ContainsFunc(*result.Counts.Decisions, func(count v3.StateCount) bool {
						return count.State == "blocked" && count.Count == 1
					}) {
					t.Fatalf("WebSocket policy refusal receipt missing: %+v", result)
				}
				return
			}
			if *result.Counts.EffectsCompleted != 4 {
				t.Fatalf("WebSocket handshake and payload receipts missing: %+v", result)
			}
		})
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

func TestV3InterceptIntentPrecedesRoundTrip(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(fmt.Sprintf("closed=%t", closed), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, "intercept", true)
			if closed {
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
			}
			cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
			cfg.FlightRecorder.RequireReceipts = true
			atEntry := make(chan bool, 1)
			rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				result, err := v3.VerifyPaths(req.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
				atEntry <- err == nil && result.Integrity == "ok" && result.Counts.EffectsUnknown != nil && *result.Counts.EffectsUnknown == 1
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{headerContentType: []string{"text/plain"}},
					Body:       io.NopCloser(strings.NewReader("example")),
				}, nil
			})
			target := net.JoinHostPort(testLoopbackIP, "443")
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+target+"/example", nil)
			resp := interceptWithRT(t, cache, pool, cfg, sc, logger, m, rt,
				&InterceptContext{Proxy: p, TargetHost: testLoopbackIP, TargetPort: "443"}, req)
			defer func() { _ = resp.Body.Close() }()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			if closed {
				if resp.StatusCode != http.StatusForbidden || len(atEntry) != 0 {
					t.Fatalf("unconfirmed receipt reached the upstream transport, status=%d", resp.StatusCode)
				}
				return
			}
			select {
			case confirmed := <-atEntry:
				if !confirmed || resp.StatusCode != http.StatusOK {
					t.Fatalf("upstream saw no confirmed intent, status=%d", resp.StatusCode)
				}
			default:
				t.Fatalf("upstream was not reached, status=%d", resp.StatusCode)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil || *result.Counts.EffectsCompleted != 2 {
				t.Fatalf("two intercepted HTTP outcomes required: %+v (%v)", result, err)
			}
		})
	}
}

func TestV3ExceptionAllowanceReceipts(t *testing.T) {
	p, writer, dir, keys := newTestV3HTTPProxy(t, "intercept", true)
	cfg := p.CurrentConfig()
	decision := receipt.EmitOpts{Method: http.MethodGet, Target: "https://api.vendor.example", Transport: "intercept"}
	first := scanner.CredentialAudienceAllow{PatternName: "first", Surface: "header", Destination: "api.vendor.example"}
	second := first
	second.PatternName = "second"
	ctx := audit.NewRequestLogContext("request")
	if err := p.recordV3CredentialAudienceAllows(cfg, ctx, []scanner.CredentialAudienceAllow{first, second, first}, decision); err != nil {
		t.Fatal(err)
	}
	cookies := []issuerCookieAllowance{{Name: "example", Patterns: []string{"first", "second"}}}
	if err := p.recordV3IssuerCookieAllows(cfg, ctx, cookies, decision); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
	if err != nil || result.Verdict != "VALID" || result.Counts.EffectsUnknown == nil || *result.Counts.EffectsUnknown != 4 {
		t.Fatalf("expected one admission per distinct allowance: %+v (%v)", result, err)
	}
	if err := p.recordV3IssuerCookieAllows(cfg, ctx, cookies, decision); err == nil {
		t.Fatal("required allowances accepted a closed writer")
	}
}

func TestV3ResponsePolicyAdmissions(t *testing.T) {
	p, writer, dir, keys := newTestV3HTTPProxy(t, TransportForward, true)
	cfg := p.CurrentConfig()
	opts := receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Target: "https://api.vendor.example", Transport: TransportForward,
		Method: http.MethodGet, Verdict: config.ActionStrip, Layer: "media_policy", Pattern: "image media rewritten",
	}
	if err := p.confirmResponseDecision(cfg, opts); err != nil {
		t.Fatal(err)
	}
	opts.ActionID = receipt.NewActionID()
	opts.Verdict, opts.Layer, opts.Pattern = config.ActionWarn, LayerSSEStream, "stream finding"
	if err := p.emitAllowPathReceipt(cfg, opts); err != nil {
		t.Fatal(err)
	}
	result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
	if err != nil || result.Counts.EffectsUnknown == nil || *result.Counts.EffectsUnknown != 2 {
		t.Fatalf("policy admissions unavailable before delivery: %+v (%v)", result, err)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if err := p.confirmResponseDecision(cfg, opts); err == nil {
		t.Fatal("closed writer admitted a response decision")
	}
}
