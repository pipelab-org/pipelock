// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestNativeCapacityStopsWebSocketAtFrameBoundaries(t *testing.T) {
	const host = "api.vendor.example"
	for _, tc := range []string{"partial upstream payload", "refused binary frame"} {
		t.Run(tc, func(t *testing.T) {
			p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+nativeWSMessageRecords+4, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
				for i := range 16 {
					pattern := audienceReceiptTestPattern(host)
					pattern.Name = fmt.Sprintf("Fixture audience %02d", i)
					cfg.DLP.Patterns = append(cfg.DLP.Patterns, pattern)
				}
			})
			p.shutdownGrace = 250 * time.Millisecond
			admission, err := p.reserveReceiptAdmission()
			if err != nil {
				t.Fatal(err)
			}
			defer admission.ReleaseNativeAdmission()
			client, clientPeer := net.Pipe()
			upstream, upstreamPeer := net.Pipe()
			for _, conn := range []net.Conn{client, clientPeer, upstream, upstreamPeer} {
				t.Cleanup(func() {
					if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Error(err)
					}
				})
			}
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(2*time.Second))
			defer cancel()
			deadline, _ := ctx.Deadline()
			for _, conn := range []net.Conn{clientPeer, upstreamPeer} {
				if err := conn.SetDeadline(deadline); err != nil {
					t.Fatal(err)
				}
			}
			relay := &wsRelay{
				clientConn: client, upstreamConn: upstream, scanner: p.ScannerPtr().Load(), proxy: p,
				cfg: p.CurrentConfig(), receiptShard: admission, scanText: true, allowBinary: true,
				hostname: host, path: "/", targetURL: "wss://" + host + "/", maxMsg: 4096,
			}
			done := make(chan wsRelayStats, 1)
			go func() { done <- relay.run(ctx) }()

			if tc == "partial upstream payload" {
				if err := ws.WriteHeader(upstreamPeer, ws.Header{Fin: true, OpCode: ws.OpText, Length: 4}); err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(upstreamPeer, "a"); err != nil {
					t.Fatal(err)
				}
				if _, err := e.ReserveNativeRecords(2 * nativeRequestRecords); !errors.Is(err, ael.ErrCapacity) {
					t.Fatalf("stop = %v, want %v", err, ael.ErrCapacity)
				}
			} else {
				payload := []byte(`{"value":"` + audienceReceiptTestCredential + `"}`)
				if err := wsutil.WriteClientMessage(clientPeer, ws.OpBinary, payload); err != nil {
					t.Fatal(err)
				}
				earlyFrame := make(chan error, 1)
				go func() {
					frame, err := ws.ReadFrame(upstreamPeer)
					if err == nil && frame.Header.OpCode != ws.OpClose {
						err = fmt.Errorf("upstream received opcode %v instead of close", frame.Header.OpCode)
					}
					earlyFrame <- err
				}()
				defer func() {
					select {
					case err := <-earlyFrame:
						if err != nil {
							t.Error(err)
						}
					case <-ctx.Done():
						t.Error("upstream did not receive its close frame")
					}
				}()
			}

			frame, err := ws.ReadFrame(clientPeer)
			code, reason := ws.ParseCloseFrameData(frame.Payload)
			if err != nil || frame.Header.OpCode != ws.OpClose || code != ws.StatusGoingAway || reason != nativeCapacityStopReason {
				t.Errorf("client terminal frame = opcode %v, code %v, reason %q, error %v", frame.Header.OpCode, code, reason, err)
			}
			if tc == "partial upstream payload" {
				frame, err := ws.ReadFrame(upstreamPeer)
				if err != nil || frame.Header.OpCode != ws.OpClose {
					t.Errorf("upstream terminal frame = %v, %v", frame.Header.OpCode, err)
				}
			}
			select {
			case stats := <-done:
				if stats.incomplete || stats.clientToServer != 0 || stats.serverToClient != 0 {
					t.Errorf("relay ended with %+v", stats)
				}
			case <-ctx.Done():
				t.Fatal("relay did not stop")
			}
			admission.ReleaseNativeAdmission()
			verifyNativeCapacityClose(t, e, dir)
		})
	}
}
