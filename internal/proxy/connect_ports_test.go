// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// countingListener accepts and holds connections, counting how many the
// proxy dialed.
func countingListener(t *testing.T) (net.Listener, *atomic.Int32) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	return ln, &accepted
}

// connectResult is the CONNECT response status and headers; the body is
// already closed.
type connectResult struct {
	StatusCode int
	Header     http.Header
}

func connectThrough(t *testing.T, proxyAddr, authority string) connectResult {
	t.Helper()
	conn := dialProxy(t, proxyAddr)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	return connectResult{StatusCode: resp.StatusCode, Header: resp.Header}
}

func TestConnectPortsAdmission(t *testing.T) {
	upstream, accepted := countingListener(t)
	_, portStr, _ := net.SplitHostPort(upstream.Addr().String())
	port, _ := strconv.Atoi(portStr)
	for _, tc := range []struct {
		name      string
		ports     []int
		enforce   bool
		authority string
		wantAllow bool
	}{
		{name: "empty_list_admits_any_port", enforce: true, authority: "127.0.0.1:" + portStr, wantAllow: true},
		{name: "listed_port_admitted", ports: []int{port}, enforce: true, authority: "127.0.0.1:" + portStr, wantAllow: true},
		{name: "unlisted_port_refused", ports: []int{port + 1}, enforce: true, authority: "127.0.0.1:" + portStr},
		{name: "leading_zero_matches_numeric_port", ports: []int{port}, enforce: true, authority: "127.0.0.1:0" + portStr, wantAllow: true},
		{name: "audit_mode_still_refuses", ports: []int{port + 1}, enforce: false, authority: "127.0.0.1:" + portStr},
		{name: "ipv6_literal_refused", ports: []int{443}, enforce: true, authority: "[::1]:" + portStr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := accepted.Load()
			enforce := tc.enforce
			proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
				cfg.Enforce = &enforce
				cfg.ForwardProxy.ConnectPorts = tc.ports
			})
			t.Cleanup(cleanup)
			resp := connectThrough(t, proxyAddr, tc.authority)
			if tc.wantAllow {
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("CONNECT status=%d reason=%q, want 200", resp.StatusCode, resp.Header.Get(blockreason.HeaderReason))
				}
				return
			}
			if resp.StatusCode != http.StatusForbidden || resp.Header.Get(blockreason.HeaderReason) != string(blockreason.ConnectPortNotAllowed) {
				t.Fatalf("CONNECT status=%d reason=%q, want 403 %s", resp.StatusCode, resp.Header.Get(blockreason.HeaderReason), blockreason.ConnectPortNotAllowed)
			}
			// The refusal is written before any dial, so a dial would already
			// be counted by the time the response arrives.
			if got := accepted.Load() - before; got != 0 {
				t.Fatalf("refused CONNECT still dialed the upstream %d time(s)", got)
			}
		})
	}
}

// The port check runs before the hostname scanners, so a host another layer
// would also refuse still reports the port as the reason, and no DNS or scan
// work is spent on it.
func TestConnectPortsCheckedBeforeHostPolicy(t *testing.T) {
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ForwardProxy.ConnectPorts = []int{443}
		cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.example"}
	})
	t.Cleanup(cleanup)
	if got := connectThrough(t, proxyAddr, "blocked.example:22").Header.Get(blockreason.HeaderReason); got != string(blockreason.ConnectPortNotAllowed) {
		t.Fatalf("blocklisted host on an unlisted port reason=%q, want %s", got, blockreason.ConnectPortNotAllowed)
	}
	// Control: on an allowed port the blocklist still decides.
	if got := connectThrough(t, proxyAddr, "blocked.example:443").Header.Get(blockreason.HeaderReason); got != string(blockreason.DomainBlocklist) {
		t.Fatalf("blocklisted host on an allowed port reason=%q, want %s", got, blockreason.DomainBlocklist)
	}
}

func TestConnectPortsRefusalIsRecorded(t *testing.T) {
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.ForwardProxy.ConnectPorts = []int{443}
	})
	t.Cleanup(cleanup)
	receipts := newReceiptProxyHelperWithMetrics(t, p.metrics)
	p.receiptEmitterPtr.Store(receipts.emitter)
	if resp := connectThrough(t, proxyAddr, "example.com:22"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", resp.StatusCode)
	}
	chain := receipts.findReceipts(t)
	if len(chain) != 1 {
		t.Fatalf("receipts=%d, want one refusal receipt", len(chain))
	}
	ar := chain[0].ActionRecord
	if ar.Verdict != config.ActionBlock || ar.Pattern != blockPatternConnectPort || ar.Layer != blockLayerConnectPort {
		t.Fatalf("refusal receipt=%+v", ar)
	}
}

// With explain_blocks on, the refusal names the control that decides it.
func TestConnectPortsExplainBlocksHint(t *testing.T) {
	for _, explain := range []bool{false, true} {
		t.Run(map[bool]string{false: "explain_off", true: "explain_on"}[explain], func(t *testing.T) {
			proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
				cfg.ExplainBlocks = &explain
				cfg.ForwardProxy.ConnectPorts = []int{443}
			})
			t.Cleanup(cleanup)
			hint := connectThrough(t, proxyAddr, "example.com:22").Header.Get("X-Pipelock-Hint")
			if explain && !strings.Contains(hint, "forward_proxy.connect_ports") {
				t.Fatalf("hint=%q, want it to name forward_proxy.connect_ports", hint)
			}
			if !explain && hint != "" {
				t.Fatalf("hint=%q with explain_blocks off, want none", hint)
			}
		})
	}
}
