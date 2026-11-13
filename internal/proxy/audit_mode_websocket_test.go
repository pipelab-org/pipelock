// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// TestAuditModeWebSocketRefusals records the WebSocket proxy with enforce false.
// A core credential in the target URL is refused at the handshake, increments
// pipelock_ws_connections_total, and writes a block receipt. A blocklisted host
// completes the handshake. The audit events are anomaly and ws_open. A core
// credential in a text frame is not echoed, and a binary frame is not echoed.
// Both leave the handshake status at 101, log ws_open, ws_blocked, and
// ws_close, increment pipelock_ws_connections_total when the relay finishes,
// and write a block receipt. The kill switch refuses the handshake and does
// not write a block receipt.
func TestAuditModeWebSocketRefusals(t *testing.T) {
	backend, closeBackend := wsEchoServer(t)
	t.Cleanup(closeBackend)
	core := auditFloorValue("core")

	type wsCase struct {
		name      string
		blocklist bool
		kill      bool
		run       func(t *testing.T, addr string) (status int, delivered bool)
		want      auditModeObservation
	}
	cases := []wsCase{
		{
			name: "core credential url",
			run: func(t *testing.T, addr string) (int, bool) {
				t.Helper()
				resp := websocketHandshake(t, addr, "ws://"+backend+"/?token="+core)
				defer func() { _ = resp.Body.Close() }()
				return resp.StatusCode, resp.StatusCode == http.StatusSwitchingProtocols
			},
			want: auditModeObservation{status: http.StatusForbidden, events: "blocked", blockMetrics: "pipelock_ws_connections_total", blockReceipt: true},
		},
		{
			name: "blocklisted host", blocklist: true,
			run: func(t *testing.T, addr string) (int, bool) {
				t.Helper()
				resp := requestWSHandshake(t, addr, backend, nil)
				defer func() { _ = resp.Body.Close() }()
				return resp.StatusCode, resp.StatusCode == http.StatusSwitchingProtocols
			},
			want: auditModeObservation{status: http.StatusSwitchingProtocols, delivered: true, events: "anomaly,ws_open"},
		},
		{
			name: "core credential frame",
			run: func(t *testing.T, addr string) (int, bool) {
				t.Helper()
				return websocketFrame(t, addr, backend, ws.OpText, []byte("token="+core))
			},
			want: auditModeObservation{status: http.StatusSwitchingProtocols, events: "ws_open,ws_blocked,ws_close", blockMetrics: "pipelock_ws_connections_total", blockReceipt: true},
		},
		{
			name: "binary frame",
			run: func(t *testing.T, addr string) (int, bool) {
				t.Helper()
				return websocketFrame(t, addr, backend, ws.OpBinary, []byte("opaque"))
			},
			want: auditModeObservation{status: http.StatusSwitchingProtocols, events: "ws_open,ws_blocked,ws_close", blockMetrics: "pipelock_ws_connections_total", blockReceipt: true},
		},
		{
			name: "kill switch", kill: true,
			run: func(t *testing.T, addr string) (int, bool) {
				t.Helper()
				resp := requestWSHandshake(t, addr, backend, nil)
				defer func() { _ = resp.Body.Close() }()
				return resp.StatusCode, resp.StatusCode == http.StatusSwitchingProtocols
			},
			want: auditModeObservation{status: http.StatusServiceUnavailable, events: "kill_switch_deny", blockMetrics: "pipelock_kill_switch_denials_total"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs auditLogBuffer
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			addr, proxy, cleanup := setupWSProxyWithLogger(t, logger, func(cfg *config.Config) {
				off := false
				cfg.Enforce = &off
				cfg.KillSwitch.Enabled = tc.kill
				if tc.blocklist {
					cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
				}
			}, nil, nil)
			t.Cleanup(cleanup)
			proxy.ks = killswitch.New(proxy.cfgPtr.Load())
			receipts := newReceiptProxyHelperWithMetrics(t, proxy.metrics)
			proxy.receiptEmitterPtr.Store(receipts.emitter)
			status, delivered := tc.run(t, addr)
			events := auditEventTypes(logs.String())
			blockMetrics := auditBlockMetrics(t, proxy.metrics)
			switch tc.name {
			case "blocklisted host":
				events = waitAuditEvents(t, &logs, "ws_open")
			case "core credential frame", "binary frame":
				events = waitAuditEvents(t, &logs, "ws_close")
				blockMetrics = waitAuditBlockMetric(t, proxy.metrics, "pipelock_ws_connections_total")
			}
			got := auditModeObservation{
				status: status, delivered: delivered, events: events,
				blockMetrics: blockMetrics, blockReceipt: auditBlockReceipt(t, receipts),
			}
			assertAuditMode(t, got, tc.want)
		})
	}
}

func websocketHandshake(t *testing.T, proxyAddr, target string) *http.Response {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp4", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET /ws?url=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", url.QueryEscape(target), proxyAddr)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func websocketFrame(t *testing.T, proxyAddr, backend string, opcode ws.OpCode, payload []byte) (int, bool) {
	t.Helper()
	conn, err := dialWSConn(proxyAddr, backend)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wsutil.WriteClientMessage(conn, opcode, payload); err != nil {
		t.Fatal(err)
	}
	reply, _, err := wsutil.ReadServerData(conn)
	return http.StatusSwitchingProtocols, err == nil && bytes.Equal(reply, payload)
}
