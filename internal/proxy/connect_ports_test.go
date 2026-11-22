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
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// dialRecorder is a listener that holds every connection it accepts and
// reports each accepted peer address, so a test can count the proxy's dials
// without timing assumptions.
type dialRecorder struct {
	ln       net.Listener
	accepted chan string
}

func newDialRecorder(t *testing.T) *dialRecorder {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &dialRecorder{ln: ln, accepted: make(chan string, 16)}
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
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
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
			r.accepted <- conn.RemoteAddr().String()
		}
	}()
	return r
}

// dialsBefore connects a sentinel and drains accepts until the sentinel
// arrives. The listener accepts in arrival order, so every dial the proxy
// made before this call is counted.
func (r *dialRecorder) dialsBefore(t *testing.T) int {
	t.Helper()
	sentinel, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(t.Context(), "tcp4", r.ln.Addr().String())
	if err != nil {
		t.Fatalf("dial sentinel: %v", err)
	}
	t.Cleanup(func() { _ = sentinel.Close() })
	want := sentinel.LocalAddr().String()
	dials := 0
	for {
		select {
		case addr := <-r.accepted:
			if addr == want {
				return dials
			}
			dials++
		case <-t.Context().Done():
			t.Fatal("sentinel was never accepted")
		}
	}
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
	for _, tc := range []struct {
		name      string
		list      string // "none", "self", "other" or "443"
		enforce   bool
		host      string // authority host; the port is the recorder's
		zeroPad   bool
		wantAllow bool
	}{
		{name: "empty_list_admits_any_port", list: "none", enforce: true, host: "127.0.0.1", wantAllow: true},
		{name: "listed_port_admitted", list: "self", enforce: true, host: "127.0.0.1", wantAllow: true},
		{name: "unlisted_port_refused", list: "other", enforce: true, host: "127.0.0.1"},
		{name: "leading_zero_matches_numeric_port", list: "self", enforce: true, host: "127.0.0.1", zeroPad: true, wantAllow: true},
		{name: "audit_mode_still_refuses", list: "other", enforce: false, host: "127.0.0.1"},
		{name: "ipv6_literal_refused", list: "443", enforce: true, host: "[::1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newDialRecorder(t)
			_, portStr, _ := net.SplitHostPort(upstream.ln.Addr().String())
			port, _ := strconv.Atoi(portStr)
			var ports []int
			switch tc.list {
			case "self":
				ports = []int{port}
			case "other":
				ports = []int{port + 1}
			case "443":
				ports = []int{443}
			}
			authority := tc.host + ":" + portStr
			if tc.zeroPad {
				authority = tc.host + ":0" + portStr
			}
			enforce := tc.enforce
			proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
				cfg.Enforce = &enforce
				cfg.ForwardProxy.ConnectPorts = ports
			})
			t.Cleanup(cleanup)
			resp := connectThrough(t, proxyAddr, authority)
			if tc.wantAllow {
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("CONNECT status=%d reason=%q, want 200", resp.StatusCode, resp.Header.Get(blockreason.HeaderReason))
				}
				return
			}
			if resp.StatusCode != http.StatusForbidden || resp.Header.Get(blockreason.HeaderReason) != string(blockreason.ConnectPortNotAllowed) {
				t.Fatalf("CONNECT status=%d reason=%q, want 403 %s", resp.StatusCode, resp.Header.Get(blockreason.HeaderReason), blockreason.ConnectPortNotAllowed)
			}
			if got := upstream.dialsBefore(t); got != 0 {
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
