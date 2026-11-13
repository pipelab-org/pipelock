// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
// events are anomaly, then tunnel_open and tunnel_close once the relay ends.
// The kill switch answers 503 with kill_switch_deny and
// does not write a block receipt.
func TestAuditModeConnectRefusals(t *testing.T) {
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
			want: auditModeObservation{status: http.StatusOK, delivered: true, events: "anomaly,tunnel_open,tunnel_close"},
		},
		{
			name: "kill switch", kill: true,
			want: auditModeObservation{status: http.StatusServiceUnavailable, events: "kill_switch_deny", blockMetrics: "pipelock_kill_switch_denials_total"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			accepted := make(chan string, 16)
			acceptDone := make(chan struct{})
			go func() {
				defer close(acceptDone)
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					select {
					case accepted <- conn.RemoteAddr().String():
					case <-t.Context().Done():
						_ = conn.Close()
						return
					}
					_ = conn.Close()
				}
			}()
			t.Cleanup(func() { _ = ln.Close(); <-acceptDone })
			host := ln.Addr().String()
			var logs bytes.Buffer
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			_, proxy, cleanup := setupForwardProxyWithLogger(t, logger, func(cfg *config.Config) {
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
			handlerDone := make(chan struct{})
			handler := proxy.buildHandler(http.NewServeMux())
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(handlerDone)
				handler.ServeHTTP(w, r)
			}))
			t.Cleanup(server.Close)
			conn := dialProxy(t, strings.TrimPrefix(server.URL, "http://"))
			t.Cleanup(func() { _ = conn.Close() })
			if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", host, host, tc.extra); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				// An established tunnel carries a ClientHello naming the CONNECT
				// host, so the tunnel ends as an ordinary relay and not as a
				// refused opaque payload.
				_, _ = conn.Write(buildClientHello("127.0.0.1"))
			}
			_ = conn.Close()
			select {
			case <-handlerDone:
			case <-time.After(5 * time.Second):
				t.Fatal("CONNECT handler did not return")
			}
			// The handler writes its last audit event when the relay ends, so
			// the evidence is read only after it returns.
			events := auditEventTypes(logs.String())
			blockMetrics := auditBlockMetrics(t, proxy.metrics)
			blockReceipt := auditBlockReceipt(t, receipts)
			// The sentinel is dialed only after the handler returns. The accept
			// loop must observe all earlier connections before the sentinel.
			sentinel, err := (&net.Dialer{}).DialContext(t.Context(), "tcp4", host)
			if err != nil {
				t.Fatal(err)
			}
			sentinelAddr := sentinel.LocalAddr().String()
			_ = sentinel.Close()
			count := 0
			for {
				select {
				case addr := <-accepted:
					if addr == sentinelAddr {
						goto drained
					}
					count++
				case <-time.After(5 * time.Second):
					t.Fatal("upstream accept loop did not reach sentinel")
				}
			}
		drained:
			if (count != 0) != tc.want.delivered || count > 1 {
				t.Fatalf("upstream accepts=%d delivered=%t", count, tc.want.delivered)
			}
			got := auditModeObservation{
				status: resp.StatusCode, delivered: resp.StatusCode == http.StatusOK && count == 1,
				events: events, blockMetrics: blockMetrics,
				blockReceipt: blockReceipt,
			}
			assertAuditMode(t, got, tc.want)
		})
	}
}
