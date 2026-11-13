// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// TestAuditModeConnectRefusals records CONNECT with enforce false.
// A core credential in the request header stays refused. The audit event is
// header_dlp, the request counter and the tunnel counter both increment, and
// no block receipt is written. The header block path records the request
// counter and the tunnel counter, then returns without a receipt. A
// blocklisted host is dialed, and the proxy writes 200 only after that dial
// returns. Delivery is the upstream accept, not the status alone. The audit
// event is anomaly. The kill switch answers 503 with kill_switch_deny and
// does not write a block receipt.
func TestAuditModeConnectRefusals(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepts atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = conn.Close()
		}
	}()
	host := ln.Addr().String()
	core := auditFloorValue("core")

	cases := []struct {
		name, extra string
		blocklist   bool
		kill        bool
		want        auditModeObservation
	}{
		{
			name: "core credential header", extra: "Authorization: Bearer " + core + "\r\n",
			want: auditModeObservation{status: http.StatusForbidden, events: "header_dlp", blockMetrics: "pipelock_requests_total,pipelock_tunnels_total"},
		},
		{
			name: "blocklisted host", blocklist: true,
			want: auditModeObservation{status: http.StatusOK, delivered: true, events: "anomaly"},
		},
		{
			name: "kill switch", kill: true,
			want: auditModeObservation{status: http.StatusServiceUnavailable, events: "kill_switch_deny", blockMetrics: "pipelock_kill_switch_denials_total"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			addr, proxy, cleanup := setupForwardProxyWithLogger(t, logger, func(cfg *config.Config) {
				off := false
				cfg.Enforce = &off
				cfg.KillSwitch.Enabled = tc.kill
				if tc.blocklist {
					cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
				}
			})
			t.Cleanup(cleanup)
			proxy.ks = killswitch.New(proxy.cfgPtr.Load())
			receipts := newReceiptProxyHelperWithMetrics(t, proxy.metrics)
			proxy.receiptEmitterPtr.Store(receipts.emitter)
			conn := dialProxy(t, addr)
			t.Cleanup(func() { _ = conn.Close() })
			if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", host, host, tc.extra); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if tc.want.delivered {
				waitTCPAccepts(t, &accepts, 1)
			} else if accepts.Load() != 0 {
				t.Fatalf("refused CONNECT reached upstream %d times", accepts.Load())
			}
			got := auditModeObservation{
				status: resp.StatusCode, delivered: resp.StatusCode == http.StatusOK && accepts.Load() == 1,
				events: auditEventTypes(logs.String()), blockMetrics: auditBlockMetrics(t, proxy.metrics),
				blockReceipt: auditBlockReceipt(t, receipts),
			}
			assertAuditMode(t, got, tc.want)
			accepts.Store(0)
		})
	}
}

func waitTCPAccepts(t *testing.T, accepts *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for accepts.Load() != want {
		select {
		case <-deadline.C:
			t.Fatalf("upstream accepts=%d want %d", accepts.Load(), want)
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-tick.C:
		}
	}
}
