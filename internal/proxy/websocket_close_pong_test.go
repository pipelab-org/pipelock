// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// pingAfterCloseServer answers a client Close by pinging first and replies
// with its own Close only after the matching Pong arrives, as RFC 6455
// section 5.5.2 lets an endpoint require. It reports whether it got the Pong.
func pingAfterCloseServer(t *testing.T, gotPong chan<- bool) (string, func()) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	const probe = "close-grace-probe"
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, _, upgradeErr := ws.UpgradeHTTP(r, w)
			if upgradeErr != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			for {
				frame, readErr := ws.ReadFrame(conn)
				if readErr != nil {
					gotPong <- false
					return
				}
				if frame.Header.OpCode == ws.OpClose {
					break
				}
			}
			if err := ws.WriteFrame(conn, ws.NewPingFrame([]byte(probe))); err != nil {
				gotPong <- false
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(testwait.Deadline(5 * time.Second)))
			reply, readErr := ws.ReadFrame(conn)
			ok := readErr == nil && reply.Header.OpCode == ws.OpPong && reply.Header.Masked &&
				string(ws.UnmaskFrame(reply).Payload) == probe
			gotPong <- ok
			if ok {
				_ = ws.WriteFrame(conn, ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusNormalClosure, "")))
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() { _ = srv.Close() }
}

func TestWSProxyAnswersUpstreamPingDuringCloseGrace(t *testing.T) {
	gotPong := make(chan bool, 1)
	backendAddr, backendCleanup := pingAfterCloseServer(t, gotPong)
	defer backendCleanup()
	proxyAddr, proxyCleanup := setupWSProxy(t, nil)
	defer proxyCleanup()

	conn := dialWS(t, proxyAddr, backendAddr)
	defer func() { _ = conn.Close() }()
	if err := ws.WriteFrame(conn, ws.MaskFrameInPlace(ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusNormalClosure, "done")))); err != nil {
		t.Fatalf("write close: %v", err)
	}

	select {
	case ok := <-gotPong:
		if !ok {
			t.Fatal("upstream did not receive a masked Pong echoing its Ping during the close grace")
		}
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("upstream never finished its Ping exchange")
	}

	_ = conn.SetReadDeadline(time.Now().Add(testwait.Deadline(5 * time.Second)))
	for {
		frame, err := ws.ReadFrame(conn)
		if err != nil {
			t.Fatalf("client did not receive the closing handshake: %v", err)
		}
		if frame.Header.OpCode == ws.OpClose {
			return
		}
		t.Fatalf("frame reached the client after it sent Close: %+v", frame.Header)
	}
}
