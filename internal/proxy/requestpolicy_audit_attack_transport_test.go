// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/authority"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type attackReadHook struct {
	once sync.Once
	rest io.Reader
	hook func()
}

func (b *attackReadHook) Read(p []byte) (int, error) {
	b.once.Do(b.hook)
	return b.rest.Read(p)
}

func (b *attackReadHook) Close() error { return nil }

func attackReload(t *testing.T, p *Proxy, cfg *config.Config) {
	t.Helper()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	if !p.Reload(cfg, sc) {
		t.Fatal("reload")
	}
}

func attackFlipEnforce(t *testing.T, p *Proxy, enforce bool) {
	t.Helper()
	cur := p.cfgPtr.Load()
	stored := *cur
	flag := enforce
	stored.Enforce = &flag
	attackReload(t, p, &stored)
}

func TestRequestPolicyAuditAttackFetchRedirect(t *testing.T) {
	t.Parallel()
	t.Run("G1_redirect_hop_block", func(t *testing.T) {
		t.Parallel()
		run := func(t *testing.T, enforce bool) policyAuditObs {
			t.Helper()
			var originHits, finalHits atomic.Int32
			final := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				finalHits.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(final.Close)
			origin := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				originHits.Add(1)
				http.Redirect(w, r, final.URL+"/v1/secret", http.StatusFound)
			}))
			t.Cleanup(origin.Close)
			host := upstreamURLHost(t, final.URL)
			cfg := attackConfig(enforce, "", "", "", config.RequestPolicyRule{
				Name: rpRuleName, Action: config.ActionBlock,
				Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodGet}, PathPrefixes: []string{"/v1/secret"}},
				Reason: "dangerous operation requires operator approval",
			})
			p, logs, receipts := policyAuditRig(t, cfg)
			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(origin.URL+"/start"), nil)
			p.buildHandler(p.buildMux()).ServeHTTP(w, req)
			// The origin is fetched before the redirect hop is decided. upstream
			// counts the final hop, which the block rule refuses.
			return policyAuditObs{status: w.Code, upstream: finalHits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics, receipts: receipts}
		}
		assertAttackPair(t, attackObserve, run(t, true), run(t, false))
	})
	t.Run("G1_observed_then_metadata", func(t *testing.T) {
		t.Parallel()
		var originHits atomic.Int32
		origin := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			originHits.Add(1)
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		}))
		t.Cleanup(origin.Close)
		host := upstreamURLHost(t, origin.URL)
		rule := config.RequestPolicyRule{
			Name: rpRuleName, Action: config.ActionBlock,
			Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodGet}},
			Reason: "dangerous operation requires operator approval",
		}
		onCfg := attackConfig(true, "", "", "", rule)
		offCfg := attackConfig(false, "", "", "", rule)
		serve := func(cfg *config.Config) policyAuditObs {
			p, logs, receipts := policyAuditRig(t, cfg)
			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(origin.URL+"/start"), nil)
			p.buildHandler(p.buildMux()).ServeHTTP(w, req)
			return policyAuditObs{status: w.Code, upstream: originHits.Load(), reason: w.Header().Get(blockreason.HeaderReason), logs: logs.String(), metrics: p.metrics, receipts: receipts}
		}
		before := originHits.Load()
		on := serve(onCfg)
		if on.status != http.StatusForbidden || on.reason != "request_policy_deny" || on.upstream != before {
			t.Fatalf("enforce status=%d reason=%q hits=%d logs=%s", on.status, on.reason, on.upstream, on.logs)
		}
		off := serve(offCfg)
		if off.status != http.StatusForbidden || off.reason != string(blockreason.SSRFMetadata) || off.upstream != before+1 {
			t.Fatalf("audit status=%d reason=%q hits=%d logs=%s", off.status, off.reason, off.upstream, off.logs)
		}
		if !strings.Contains(off.logs, "would_block=true") {
			t.Fatalf("audit logs=%s", off.logs)
		}
		if _, _, found := attackBlockedFields(off.logs); found {
			t.Fatalf("metadata refusal wrote request_policy blocked: %s", off.logs)
		}
		if _, ok := attackPolicyReceipt(t, off.receipts); ok {
			t.Fatal("metadata refusal wrote a request_policy block receipt")
		}
	})
}

func attackConnect(t *testing.T, p *Proxy, target string) policyAuditObs {
	t.Helper()
	var hits atomic.Int32
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			hits.Add(1)
			_ = conn.Close()
		}
	}()
	if target == "" {
		target = ln.Addr().String()
	}
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		p.buildHandler(http.NewServeMux()).ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	conn := dialProxy(t, strings.TrimPrefix(server.URL, "http://"))
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	_ = conn.Close()
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("CONNECT handler did not return")
	}
	if resp.StatusCode == http.StatusOK {
		deadline := time.Now().Add(5 * time.Second)
		for hits.Load() == 0 && time.Now().Before(deadline) {
			runtime.Gosched()
		}
	}
	return policyAuditObs{status: resp.StatusCode, upstream: hits.Load(), reason: resp.Header.Get("X-Pipelock-Block-Reason")}
}

func TestRequestPolicyAuditAttackConnectInner(t *testing.T) {
	t.Parallel()
	// The inner request is decided by newInterceptHandler with the config
	// CONNECT copies into InterceptContext. Enforce true never opens the
	// tunnel, so the inner oracle is that handler rather than bytes inside a
	// TLS intercept session.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	connectRule := config.RequestPolicyRule{
		Name: rpRuleName, Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodConnect}},
		Reason: "host blocked for agent runtime",
	}
	innerRule := attackDisc(rpTestHost, http.MethodPost, "/v1/upload")
	for _, enforce := range []bool{false, true} {
		cfg := attackConfig(enforce, config.ActionBlock, config.ActionBlock, "", connectRule, innerRule)
		p, logs, receipts := policyAuditRig(t, cfg)
		obs := attackConnect(t, p, "")
		obs.logs = logs.String()
		obs.metrics = p.metrics
		obs.receipts = receipts
		if enforce {
			if obs.status != http.StatusForbidden || obs.upstream != 0 {
				t.Fatalf("CONNECT enforce status=%d upstream=%d logs=%s", obs.status, obs.upstream, obs.logs)
			}
		} else if obs.status != http.StatusOK || obs.upstream != 1 || !strings.Contains(obs.logs, "would_block=true") {
			t.Fatalf("CONNECT audit status=%d upstream=%d logs=%s", obs.status, obs.upstream, obs.logs)
		}
	}
	match := []byte(`{"action":"deleteAll"}`)
	bad := []byte("not-json")
	onMatch := attackIntercept(t, attackConfig(true, config.ActionBlock, config.ActionBlock, "", innerRule), "https://"+rpTestHost+"/v1/upload", match, nil)
	offMatch := attackIntercept(t, attackConfig(false, config.ActionBlock, config.ActionBlock, "", innerRule), "https://"+rpTestHost+"/v1/upload", match, nil)
	assertAttackPair(t, attackObserve, onMatch, offMatch)
	onBad := attackIntercept(t, attackConfig(true, config.ActionBlock, config.ActionAllow, "", innerRule), "https://"+rpTestHost+"/v1/upload", bad, nil)
	offBad := attackIntercept(t, attackConfig(false, config.ActionBlock, config.ActionAllow, "", innerRule), "https://"+rpTestHost+"/v1/upload", bad, nil)
	assertAttackPair(t, attackRefuse, onBad, offBad)
}

func TestRequestPolicyAuditAttackReverseRewrite(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	var gotPath atomic.Value
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotPath.Store(r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	parsed, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/upstream-base"
	rule := func(enforce bool) *config.Config {
		return attackConfig(enforce, "", "", "", config.RequestPolicyRule{
			Name: rpRuleName, Action: config.ActionBlock,
			Route: config.RequestPolicyRoute{
				Hosts:        []string{parsed.Hostname()},
				Methods:      []string{http.MethodDelete},
				PathPrefixes: []string{"/upstream-base/jobs"},
			},
			Reason: "dangerous operation requires operator approval",
		})
	}
	serve := func(cfg *config.Config) policyAuditObs {
		p, logs, receipts := policyAuditRig(t, cfg)
		handler := NewReverseProxy(parsed, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
		handler.SetRequestPolicyFn(p.ApplyRequestPolicy)
		handler.SetRequestPolicyPrepareFn(p.PrepareRequestPolicyBody)
		handler.SetReceiptEmitter(&p.receiptEmitterPtr)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "http://"+rpTestHost+"/jobs", nil)
		req.Host = rpTestHost
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return policyAuditObs{status: w.Code, upstream: hits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics, receipts: receipts}
	}
	on := serve(rule(true))
	if on.status != http.StatusForbidden || on.upstream != 0 || on.reason != "request_policy_deny" {
		t.Fatalf("enforce status=%d upstream=%d reason=%q logs=%s", on.status, on.upstream, on.reason, on.logs)
	}
	off := serve(rule(false))
	if off.status != http.StatusOK || off.upstream != 1 || !strings.Contains(off.logs, "would_block=true") {
		t.Fatalf("audit status=%d upstream=%d logs=%s", off.status, off.upstream, off.logs)
	}
	if path, _ := gotPath.Load().(string); path != "/upstream-base/jobs" {
		t.Fatalf("upstream path = %q", path)
	}
}

func attackWS(t *testing.T, enforce bool, allowBinary bool, rules []config.RequestPolicyRule, parse string) (string, *attackLogBuffer) {
	t.Helper()
	addr, logs, _ := attackWSProxy(t, enforce, allowBinary, rules, parse)
	return addr, logs
}

func attackWSProxy(t *testing.T, enforce bool, allowBinary bool, rules []config.RequestPolicyRule, parse string) (string, *attackLogBuffer, *Proxy) {
	t.Helper()
	logs := &attackLogBuffer{}
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, logs)
	if err != nil {
		t.Fatal(err)
	}
	addr, p, cleanup := setupWSProxyWithLogger(t, logger, func(cfg *config.Config) {
		flag := enforce
		cfg.Enforce = &flag
		cfg.RequestPolicy.Enabled = true
		cfg.RequestPolicy.OnParseError = parse
		cfg.RequestPolicy.OnOpaqueOperation = config.ActionAllow
		cfg.RequestPolicy.Rules = rules
		cfg.RequestBodyScanning.Enabled = false
		cfg.WebSocketProxy.AllowBinaryFrames = allowBinary
	}, nil, nil)
	t.Cleanup(logger.Close)
	t.Cleanup(cleanup)
	return addr, logs, p
}

func attackWSClose(t *testing.T, conn net.Conn) ws.StatusCode {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := wsutil.ReadServerData(conn)
	var closed wsutil.ClosedError
	if !errors.As(err, &closed) {
		t.Fatalf("close error = %v", err)
	}
	return closed.Code
}

func TestRequestPolicyAuditAttackWebSocketFrames(t *testing.T) {
	t.Parallel()
	backend, frames, _, handshake := wsRecordingServerWithHandshake(t)
	host, _, err := net.SplitHostPort(backend)
	if err != nil {
		t.Fatal(err)
	}
	route := config.RequestPolicyRule{
		Name: rpRuleName, Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodGet}},
		Reason: "dangerous operation requires operator approval",
	}
	disc := attackDisc(host, http.MethodGet, "/")
	t.Run("G4_handshake", func(t *testing.T) {
		for _, enforce := range []bool{true, false} {
			addr, logs := attackWS(t, enforce, false, []config.RequestPolicyRule{route}, config.ActionBlock)
			resp := requestWSHandshake(t, addr, backend, nil)
			if enforce {
				if resp.StatusCode != http.StatusForbidden || handshake() != nil {
					t.Fatalf("enforce status=%d handshake=%v logs=%s", resp.StatusCode, handshake() != nil, logs.String())
				}
			} else if resp.StatusCode != http.StatusSwitchingProtocols || !strings.Contains(logs.String(), "would_block=true") {
				t.Fatalf("audit status=%d logs=%s", resp.StatusCode, logs.String())
			}
			_ = resp.Body.Close()
		}
	})
	t.Run("G4_text_match", func(t *testing.T) {
		for _, enforce := range []bool{true, false} {
			addr, logs := attackWS(t, enforce, false, []config.RequestPolicyRule{disc}, config.ActionAllow)
			conn := dialWS(t, addr, backend)
			before := frames()
			if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(`{"action":"deleteAll"}`)); err != nil {
				t.Fatal(err)
			}
			if enforce {
				if code := attackWSClose(t, conn); code != ws.StatusPolicyViolation {
					t.Fatalf("close=%d", code)
				}
			} else {
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				reply, op, err := wsutil.ReadServerData(conn)
				if err != nil || op != ws.OpText || string(reply) != `{"action":"deleteAll"}` {
					t.Fatalf("echo op=%v reply=%q err=%v logs=%s", op, reply, err, logs.String())
				}
				deadline := time.Now().Add(5 * time.Second)
				for frames() == before && time.Now().Before(deadline) {
					runtime.Gosched()
				}
				if frames() != before+1 || !strings.Contains(logs.String(), "would_block=true") {
					t.Fatalf("frames=%d logs=%s", frames(), logs.String())
				}
			}
			_ = conn.Close()
		}
	})
	t.Run("G4_reload_on_open_socket", func(t *testing.T) {
		frame := []byte(`{"action":"deleteAll"}`)
		// Admitted in audit mode: the first frame is observed, and the same
		// socket refuses the next one once a reload turns enforcement on.
		addr, logs, p := attackWSProxy(t, false, false, []config.RequestPolicyRule{disc}, config.ActionAllow)
		conn := dialWS(t, addr, backend)
		if err := wsutil.WriteClientMessage(conn, ws.OpText, frame); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if reply, _, err := wsutil.ReadServerData(conn); err != nil || !bytes.Equal(reply, frame) {
			t.Fatalf("audit frame reply=%q err=%v logs=%s", reply, err, logs.String())
		}
		attackFlipEnforce(t, p, true)
		before := frames()
		if err := wsutil.WriteClientMessage(conn, ws.OpText, frame); err != nil {
			t.Fatal(err)
		}
		if code := attackWSClose(t, conn); code != ws.StatusPolicyViolation {
			t.Fatalf("close after reload to enforce=%d logs=%s", code, logs.String())
		}
		if frames() != before {
			t.Fatalf("frame reached upstream after reload to enforce: %d -> %d", before, frames())
		}
		_ = conn.Close()

		// Admitted under enforcement: a reload to audit mode does not loosen
		// the open socket.
		addr, logs, p = attackWSProxy(t, true, false, []config.RequestPolicyRule{disc}, config.ActionAllow)
		conn = dialWS(t, addr, backend)
		attackFlipEnforce(t, p, false)
		before = frames()
		if err := wsutil.WriteClientMessage(conn, ws.OpText, frame); err != nil {
			t.Fatal(err)
		}
		if code := attackWSClose(t, conn); code != ws.StatusPolicyViolation {
			t.Fatalf("close after reload to audit=%d logs=%s", code, logs.String())
		}
		if frames() != before {
			t.Fatalf("frame reached upstream on a socket admitted under enforcement: %d -> %d", before, frames())
		}
		_ = conn.Close()
	})
	t.Run("G4_text_not_json", func(t *testing.T) {
		for _, enforce := range []bool{true, false} {
			addr, _ := attackWS(t, enforce, false, []config.RequestPolicyRule{disc}, config.ActionBlock)
			conn := dialWS(t, addr, backend)
			if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte("not-json")); err != nil {
				t.Fatal(err)
			}
			if code := attackWSClose(t, conn); code != ws.StatusPolicyViolation {
				t.Fatalf("enforce=%t close=%d", enforce, code)
			}
			_ = conn.Close()
		}
	})
	t.Run("G4_fragmented_text", func(t *testing.T) {
		payload := []byte(`{"action":"deleteAll"}`)
		for _, enforce := range []bool{true, false} {
			addr, logs := attackWS(t, enforce, false, []config.RequestPolicyRule{disc}, config.ActionAllow)
			conn := dialWS(t, addr, backend)
			writeMaskedClientFrame(t, conn, false, ws.OpText, payload[:8])
			writeMaskedClientFrame(t, conn, true, ws.OpContinuation, payload[8:])
			if enforce {
				if code := attackWSClose(t, conn); code != ws.StatusPolicyViolation {
					t.Fatalf("close=%d logs=%s", code, logs.String())
				}
			} else {
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				reply, _, err := wsutil.ReadServerData(conn)
				if err != nil || string(reply) != string(payload) {
					t.Fatalf("fragment echo=%q err=%v logs=%s", reply, err, logs.String())
				}
			}
			_ = conn.Close()
		}
	})
	t.Run("G4_binary_default", func(t *testing.T) {
		for _, enforce := range []bool{true, false} {
			addr, _ := attackWS(t, enforce, false, []config.RequestPolicyRule{disc}, config.ActionBlock)
			conn := dialWS(t, addr, backend)
			if err := wsutil.WriteClientMessage(conn, ws.OpBinary, []byte(`{"action":"deleteAll"}`)); err != nil {
				t.Fatal(err)
			}
			if code := attackWSClose(t, conn); code != ws.StatusPolicyViolation {
				t.Fatalf("enforce=%t close=%d", enforce, code)
			}
			_ = conn.Close()
		}
	})
	t.Run("G4_binary_allowed", func(t *testing.T) {
		body := []byte(`{"action":"deleteAll"}`)
		for _, enforce := range []bool{true, false} {
			addr, logs := attackWS(t, enforce, true, []config.RequestPolicyRule{disc}, config.ActionBlock)
			conn := dialWS(t, addr, backend)
			if err := wsutil.WriteClientMessage(conn, ws.OpBinary, body); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			reply, op, err := wsutil.ReadServerData(conn)
			if err != nil || op != ws.OpBinary || !bytes.Equal(reply, body) {
				t.Fatalf("enforce=%t op=%v reply=%q err=%v logs=%s", enforce, op, reply, err, logs.String())
			}
			if strings.Contains(logs.String(), "would_block=true") || strings.Contains(logs.String(), `"scanner":"request_policy"`) {
				t.Fatalf("binary frame was operation-inspected: %s", logs.String())
			}
			_ = conn.Close()
		}
	})
}

func TestRequestPolicyAuditAttackReload(t *testing.T) {
	t.Parallel()
	plain := []byte(`{"action":"deleteAll"}`)
	rules := func(host string) []config.RequestPolicyRule {
		return []config.RequestPolicyRule{attackRoute(host, http.MethodPost, "/v1/items", config.ActionBlock), attackDisc(host, http.MethodPost, "/v1/items")}
	}
	for _, transport := range []string{"forward", "reverse"} {
		t.Run("H1_admitted_audit/"+transport, func(t *testing.T) {
			t.Parallel()
			obs, _ := runAttackExchange(t, transport, false, attackExchange{
				method: http.MethodPost, path: "/v1/items",
				parse: config.ActionAllow, opaque: config.ActionAllow, rules: rules,
				bodyFrom: func(p *Proxy) io.Reader {
					return &attackReadHook{rest: bytes.NewReader(plain), hook: func() { attackFlipEnforce(t, p, true) }}
				},
			})
			// Enforcement turned on while the body was being read: the live
			// flag wins and the request refuses.
			if obs.status != http.StatusForbidden || obs.upstream != 0 || obs.reason != "request_policy_deny" || strings.Contains(obs.logs, "would_block=true") {
				t.Fatalf("admitted audit, reloaded to enforce status=%d upstream=%d reason=%q logs=%s", obs.status, obs.upstream, obs.reason, obs.logs)
			}
		})
		t.Run("H1_admitted_enforce/"+transport, func(t *testing.T) {
			t.Parallel()
			obs, _ := runAttackExchange(t, transport, true, attackExchange{
				method: http.MethodPost, path: "/v1/items",
				parse: config.ActionAllow, opaque: config.ActionAllow, rules: rules,
				bodyFrom: func(p *Proxy) io.Reader {
					return &attackReadHook{rest: bytes.NewReader(plain), hook: func() { attackFlipEnforce(t, p, false) }}
				},
			})
			if obs.status != http.StatusForbidden || obs.upstream != 0 || obs.reason != "request_policy_deny" {
				t.Fatalf("admitted enforce status=%d upstream=%d reason=%q logs=%s", obs.status, obs.upstream, obs.reason, obs.logs)
			}
		})
	}
	t.Run("H2_connect_snapshot", func(t *testing.T) {
		t.Parallel()
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		host, _, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = ln.Close()
		connectRule := config.RequestPolicyRule{
			Name: rpRuleName, Action: config.ActionBlock,
			Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodConnect}},
			Reason: "host blocked for agent runtime",
		}
		inner := attackDisc(rpTestHost, http.MethodPost, "/v1/upload")
		body := []byte(`{"action":"deleteAll"}`)
		admittedOff := attackConfig(false, config.ActionAllow, config.ActionAllow, "", connectRule, inner)
		p, _, _ := policyAuditRig(t, admittedOff)
		outer := attackConnect(t, p, "")
		if outer.status != http.StatusOK || outer.upstream != 1 {
			t.Fatalf("admitted audit CONNECT status=%d upstream=%d", outer.status, outer.upstream)
		}
		attackReload(t, p, attackConfig(true, config.ActionAllow, config.ActionAllow, "", connectRule, inner))
		ic := &InterceptContext{
			TargetHost: rpTestHost, TargetPort: "443", Config: admittedOff, Scanner: p.scannerPtr.Load(),
			Logger: p.logger, Metrics: p.metrics, Proxy: p, RequestID: "audit-h2", ClientIP: "192.0.2.1",
		}
		// The tunnel was admitted in audit mode and outlives a reload to
		// enforce: its inner requests refuse from then on.
		handler := newInterceptHandler(ic, roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("inner request reached upstream after reload to enforce")
			return nil, nil
		}))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+rpTestHost+"/v1/upload", bytes.NewReader(body))
		req.Host = rpTestHost
		req.Header.Set(headerContentType, contentTypeJSON)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("inner after reload to enforce status=%d", w.Code)
		}
		admittedOn := attackConfig(true, config.ActionAllow, config.ActionAllow, "", connectRule, inner)
		p2, _, _ := policyAuditRig(t, admittedOn)
		attackReload(t, p2, attackConfig(false, config.ActionAllow, config.ActionAllow, "", connectRule, inner))
		ic2 := &InterceptContext{
			TargetHost: rpTestHost, TargetPort: "443", Config: admittedOn, Scanner: p2.scannerPtr.Load(),
			Logger: p2.logger, Metrics: p2.metrics, Proxy: p2, RequestID: "audit-h2b", ClientIP: "192.0.2.1",
		}
		handler2 := newInterceptHandler(ic2, roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("enforced inner reached upstream")
			return nil, nil
		}))
		req2 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+rpTestHost+"/v1/upload", bytes.NewReader(body))
		req2.Host = rpTestHost
		req2.Header.Set(headerContentType, contentTypeJSON)
		w2 := httptest.NewRecorder()
		handler2.ServeHTTP(w2, req2)
		if w2.Code != http.StatusForbidden {
			t.Fatalf("admitted enforce inner status=%d", w2.Code)
		}
	})
	t.Run("H3_rule_removed_during_read", func(t *testing.T) {
		t.Parallel()
		for _, transport := range []string{"forward", "reverse"} {
			t.Run(transport, func(t *testing.T) {
				t.Parallel()
				body := bytes.Repeat(plain, 4)
				ex := attackExchange{
					method: http.MethodPost, path: "/v1/items", body: body, maxBody: 8,
					contentLengthSet: true,
					parse:            config.ActionAllow, opaque: config.ActionAllow, rules: rules,
					bodyFrom: func(p *Proxy) io.Reader {
						return &attackReadHook{rest: bytes.NewReader(body), hook: func() {
							live := attackConfig(false, config.ActionAllow, config.ActionAllow, "")
							live.RequestPolicy.Rules = nil
							live.RequestBodyScanning.MaxBodyBytes = 8
							attackReload(t, p, live)
						}}
					},
				}
				on, _ := runAttackExchange(t, transport, true, ex)
				off, _ := runAttackExchange(t, transport, false, ex)
				if on.status != http.StatusForbidden || off.status != http.StatusForbidden || on.upstream != 0 || off.upstream != 0 || on.reason != "request_policy_deny" || off.reason != on.reason {
					t.Fatalf("status/upstream/reason enforce=%d/%d/%q audit=%d/%d/%q logs=%s | %s", on.status, on.upstream, on.reason, off.status, off.upstream, off.reason, on.logs, off.logs)
				}
				onClass, onWhy, onFound := attackBlockedFields(on.logs)
				offClass, offWhy, offFound := attackBlockedFields(off.logs)
				if !onFound || !offFound || onClass != "protective" || offClass != onClass || offWhy != onWhy || onWhy != "body_uninspectable" {
					t.Fatalf("blocked enforce=%q/%q audit=%q/%q", onClass, onWhy, offClass, offWhy)
				}
				onActions, offActions := attackActions(t, on.metrics), attackActions(t, off.metrics)
				if onActions["body_uninspectable"] != config.ActionBlock || offActions["body_uninspectable"] != config.ActionBlock {
					t.Fatalf("actions enforce=%v audit=%v", onActions, offActions)
				}
			})
		}
	})
}

func TestRequestPolicyAuditAttackShadow(t *testing.T) {
	t.Parallel()
	shadowDisc := func(host string) config.RequestPolicyRule {
		rule := attackDisc(host, http.MethodPost, "/v1/items")
		rule.Name = "shadow-disc"
		rule.Shadow = true
		return rule
	}
	t.Run("I_shadow_uninspectable", func(t *testing.T) {
		t.Parallel()
		for _, transport := range []string{"forward", "reverse"} {
			runAttackPair(t, transport, attackRelease, attackExchange{
				method: http.MethodPost, path: "/v1/items", body: []byte("not-json"),
				parse: config.ActionBlock, opaque: config.ActionAllow,
				rules: func(host string) []config.RequestPolicyRule { return []config.RequestPolicyRule{shadowDisc(host)} },
			})
		}
	})
	t.Run("I_shadow_uninspectable_plus_enforced_route", func(t *testing.T) {
		t.Parallel()
		for _, transport := range []string{"forward", "reverse"} {
			// The enforced route block is the only refusal. Audit must forward it.
			runAttackPair(t, transport, attackObserve, attackExchange{
				method: http.MethodPost, path: "/v1/items", body: []byte("not-json"),
				parse: config.ActionBlock, opaque: config.ActionAllow,
				rules: func(host string) []config.RequestPolicyRule {
					return []config.RequestPolicyRule{
						attackRoute(host, http.MethodPost, "/v1/items", config.ActionBlock),
						shadowDisc(host),
					}
				},
			})
		}
	})
	perms := [][]string{
		{"enforced", "shadow", "unmarked"},
		{"enforced", "unmarked", "shadow"},
		{"shadow", "enforced", "unmarked"},
		{"shadow", "unmarked", "enforced"},
		{"unmarked", "enforced", "shadow"},
		{"unmarked", "shadow", "enforced"},
	}
	for _, perm := range perms {
		perm := perm
		t.Run("I_order_"+strings.Join(perm, "_"), func(t *testing.T) {
			t.Parallel()
			for _, transport := range []string{"forward", "reverse"} {
				t.Run(transport, func(t *testing.T) {
					t.Parallel()
					runAttackPair(t, transport, attackRefuse, attackExchange{
						method: http.MethodPost, path: "/v1/items", body: []byte("[1]"),
						parse: config.ActionAllow, opaque: config.ActionBlock,
						rules: func(host string) []config.RequestPolicyRule {
							byName := map[string]config.RequestPolicyRule{
								"enforced": attackRoute(host, http.MethodPost, "/v1/items", config.ActionBlock),
								"shadow": func() config.RequestPolicyRule {
									rule := attackRoute(host, http.MethodPost, "/v1/items", config.ActionBlock)
									rule.Name = "shadow-block"
									rule.Shadow = true
									return rule
								}(),
								"unmarked": attackDisc(host, http.MethodPost, "/v1/items"),
							}
							out := make([]config.RequestPolicyRule, 0, len(perm))
							for _, name := range perm {
								out = append(out, byName[name])
							}
							return out
						},
					})
				})
			}
		})
	}
}

func TestRequestPolicyAuditAttackEvidence(t *testing.T) {
	t.Parallel()
	t.Run("J_unmarked_parity", func(t *testing.T) {
		t.Parallel()
		ex := attackExchange{
			method: http.MethodPost, path: "/v1/items", body: []byte("not-json"),
			parse: config.ActionBlock, opaque: config.ActionAllow,
			rules: func(host string) []config.RequestPolicyRule {
				return []config.RequestPolicyRule{attackRoute(host, http.MethodPost, "/v1/items", config.ActionBlock), attackDisc(host, http.MethodPost, "/v1/items")}
			},
		}
		on, _ := runAttackExchange(t, "forward", true, ex)
		off, _ := runAttackExchange(t, "forward", false, ex)
		assertAttackPair(t, attackRefuse, on, off)
		if attackCounter(t, on.metrics, "pipelock_requests_total", "result", "blocked") != attackCounter(t, off.metrics, "pipelock_requests_total", "result", "blocked") {
			t.Fatal("blocked request counter differs")
		}
		if attackCounter(t, on.metrics, "pipelock_scanner_hits_total", "scanner", blockLayerRequestPolicy) != attackCounter(t, off.metrics, "pipelock_scanner_hits_total", "scanner", blockLayerRequestPolicy) {
			t.Fatal("scanner hit counter differs")
		}
	})
	t.Run("J_authority_after_observe", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(backend.Close)
		cfg := attackConfig(false, "", "", "", attackRoute(rpTestHost, http.MethodDelete, "/v1/jobs", config.ActionBlock))
		p, logs, receipts := policyAuditRig(t, cfg)
		p.authorityVerifier = proxyAuthorityVerifierFunc(func(context.Context, authority.Request) authority.Result {
			return authority.Result{Decision: authority.DecisionDeny, Reason: authority.ReasonActionMismatch}
		})
		installForwardTestDialer(p, backend.Listener.Addr().String())
		req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "http://"+rpTestHost+"/v1/jobs/1", nil)
		req.Header.Set(authority.HTTPHeader, "grant")
		req.Header.Set(AgentHeader, "agent-a")
		w := httptest.NewRecorder()
		p.buildHandler(http.NewServeMux()).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || hits.Load() != 0 || w.Header().Get(blockreason.HeaderReason) != string(blockreason.AuthorityMismatch) {
			t.Fatalf("status=%d hits=%d reason=%q logs=%s", w.Code, hits.Load(), w.Header().Get(blockreason.HeaderReason), logs.String())
		}
		if !strings.Contains(logs.String(), "would_block=true") {
			t.Fatalf("logs=%s", logs.String())
		}
		if _, _, found := attackBlockedFields(logs.String()); found {
			t.Fatalf("authority refusal wrote request_policy blocked: %s", logs.String())
		}
		foundAuthority := false
		for _, got := range receipts.findReceipts(t) {
			if got.ActionRecord.Layer == blockLayerRequestPolicy && got.ActionRecord.Verdict == config.ActionBlock {
				t.Fatalf("request_policy receipt %+v", got.ActionRecord)
			}
			if got.ActionRecord.Layer == blockLayerAuthority && got.ActionRecord.Verdict == config.ActionBlock {
				foundAuthority = true
			}
		}
		if !foundAuthority {
			t.Fatal("missing authority block receipt")
		}
	})
	t.Run("J_contract_after_observe", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(backend.Close)
		cfg := attackConfig(false, "", "", "", attackRoute(rpTestHost, http.MethodDelete, "/v1/jobs", config.ActionBlock))
		p, logs, receipts := policyAuditRig(t, cfg)
		p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, contractruntimetest.HTTPEnforceRule("r-other", "other.example.com", "/v1", http.MethodPost)))
		installForwardTestDialer(p, backend.Listener.Addr().String())
		req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "http://"+rpTestHost+"/v1/jobs/1", nil)
		req.Header.Set(AgentHeader, "agent-a")
		w := httptest.NewRecorder()
		p.buildHandler(http.NewServeMux()).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || hits.Load() != 0 || w.Header().Get(blockreason.HeaderReason) != contractDefaultDenyReason {
			t.Fatalf("status=%d hits=%d reason=%q logs=%s", w.Code, hits.Load(), w.Header().Get(blockreason.HeaderReason), logs.String())
		}
		if _, _, found := attackBlockedFields(logs.String()); found || !strings.Contains(logs.String(), "would_block=true") {
			t.Fatalf("logs=%s", logs.String())
		}
		if _, ok := attackPolicyReceipt(t, receipts); ok {
			t.Fatal("contract refusal wrote a request_policy block receipt")
		}
	})
	t.Run("J_kill_after_observe", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/secret" {
				hits.Add(1)
			}
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(backend.Close)
		host := upstreamURLHost(t, backend.URL)
		cfg := attackConfig(false, "", "", "", config.RequestPolicyRule{
			Name: rpRuleName, Action: config.ActionBlock,
			Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodGet}},
			Reason: "dangerous operation requires operator approval",
		})
		cfg.KillSwitch.Enabled = true
		p, logs, _ := policyAuditRig(t, cfg)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(backend.URL+"/v1/secret"), nil)
		w := httptest.NewRecorder()
		p.handleFetch(w, req)
		if w.Code == http.StatusOK || hits.Load() != 0 || !strings.Contains(logs.String(), "would_block=true") || !strings.Contains(logs.String(), "kill_switch") {
			t.Fatalf("status=%d hits=%d logs=%s", w.Code, hits.Load(), logs.String())
		}
		if _, _, found := attackBlockedFields(logs.String()); found {
			t.Fatalf("kill switch wrote request_policy blocked: %s", logs.String())
		}
	})
	t.Run("J_dial_ssrf_after_observe", func(t *testing.T) {
		t.Parallel()
		cfg := attackConfig(false, "", "", "", config.RequestPolicyRule{
			Name: rpRuleName, Action: config.ActionBlock,
			Route:  config.RequestPolicyRoute{Hosts: []string{"rebind.test"}, Methods: []string{http.MethodGet}},
			Reason: "dangerous operation requires operator approval",
		})
		cfg.Internal = []string{"127.0.0.0/8"}
		cfg.DNS.HostOverrides = map[string][]string{"rebind.test": {"203.0.113.10"}}
		p, logs, _ := policyAuditRig(t, cfg)
		p.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			ip := net.ParseIP("127.0.0.1")
			return nil, newSSRFDialBlockError(req.Context(), req.URL.Hostname(), ip, ssrfDialBlockDetail(req.URL.Hostname(), ip))
		})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url=http://rebind.test/v1/secret", nil)
		w := httptest.NewRecorder()
		p.handleFetch(w, req)
		if w.Code != http.StatusForbidden || !strings.Contains(logs.String(), "would_block=true") {
			t.Fatalf("status=%d reason=%q logs=%s", w.Code, w.Header().Get(blockreason.HeaderReason), logs.String())
		}
		if _, _, found := attackBlockedFields(logs.String()); found {
			t.Fatalf("dial refusal wrote request_policy blocked: %s", logs.String())
		}
	})
	t.Run("J_require_receipts_after_observe", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			_, _ = w.Write([]byte("ok"))
		}))
		t.Cleanup(backend.Close)
		host := upstreamURLHost(t, backend.URL)
		cfg := attackConfig(false, "", "", "", config.RequestPolicyRule{
			Name: rpRuleName, Action: config.ActionBlock,
			Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodGet}, PathPrefixes: []string{"/v1/secret"}},
			Reason: "dangerous operation requires operator approval",
		})
		cfg.FlightRecorder.RequireReceipts = true
		cfg.ResponseScanning.Enabled = false
		p, logs, receipts := policyAuditRig(t, cfg)
		if err := receipts.rec.Close(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(backend.URL+"/v1/secret"), nil)
		w := httptest.NewRecorder()
		p.handleFetch(w, req)
		if w.Code != http.StatusForbidden || hits.Load() != 0 || w.Header().Get(blockreason.HeaderReason) != string(blockreason.ReceiptEmissionFailed) {
			t.Fatalf("status=%d hits=%d reason=%q logs=%s", w.Code, hits.Load(), w.Header().Get(blockreason.HeaderReason), logs.String())
		}
		if !strings.Contains(logs.String(), "would_block=true") {
			t.Fatalf("logs=%s", logs.String())
		}
		if _, _, found := attackBlockedFields(logs.String()); found {
			t.Fatalf("receipt refusal wrote request_policy blocked: %s", logs.String())
		}
	})
}

func attackCounter(t *testing.T, m *metrics.Metrics, familyName, label, value string) float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var sum float64
	for _, family := range families {
		if family.GetName() != familyName {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricHasLabel(metric, label, value) {
				sum += metricValue(metric)
			}
		}
	}
	return sum
}

func TestRequestPolicyAuditAttackMCPBytes(t *testing.T) {
	t.Parallel()
	timeField := regexp.MustCompile(`"time":"[^"]*"`)
	normalize := func(line string) string {
		return timeField.ReplaceAllString(strings.TrimSpace(line), `"time":"2023-11-14T22:13:20Z"`)
	}
	hint := "Edit the exact matched entry under `request_policy.rules` (the event reason names it), narrowing its route/predicate or changing that rule's action. For a body in a content coding Pipelock does not decode, tune `request_policy.on_undecodable_encoding`. For parser/opaque findings, tune only `request_policy.on_parse_error` or `request_policy.on_opaque_operation`; allowing either is broader and fail-open for matching body predicates."
	classed := `{"level":"warn","component":"pipelock","event":"blocked","method":"MCP","resource":"[redacted]","scanner":"request_policy","reason":"disc-block","agent":"mcp-fixture","agent_auth":"unknown","remediation_hint":"` + hint + `","block_class":"infrastructure_error","protocol":"mcp","transport":"mcp_stdio","direction":"input","time":"2023-11-14T22:13:20Z","message":"request blocked"}`
	empty := `{"level":"warn","component":"pipelock","event":"blocked","method":"MCP","resource":"[redacted]","scanner":"request_policy","reason":"disc-block","agent":"mcp-fixture","agent_auth":"unknown","remediation_hint":"` + hint + `","protocol":"mcp","transport":"mcp_stdio","direction":"input","time":"2023-11-14T22:13:20Z","message":"request blocked"}`
	for _, tc := range []struct {
		name  string
		class string
		want  string
	}{
		{name: "K_classed", class: audit.BlockClassInfrastructureError, want: classed},
		{name: "K_empty_class", class: "", want: empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &buf)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			ctx, err := audit.NewMCPLogContext("MCP", "tools/call", "mcp-fixture")
			if err != nil {
				t.Fatal(err)
			}
			ctx = ctx.WithMCPRoute("mcp_stdio", "input")
			logger.LogBlockedDetail(ctx, blockLayerRequestPolicy, attackDiscRule, audit.BlockDetail{Class: tc.class})
			if got := normalize(buf.String()); got != tc.want {
				t.Fatalf("got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// attackLogBuffer is an audit stream the WebSocket relay writes while the test
// reads it.
type attackLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *attackLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *attackLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
