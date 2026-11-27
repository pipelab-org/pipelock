// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// requireWSCloseCode reads the next server message and requires the proxy's
// Close frame with want. A read deadline, a reset, a bare EOF or a data
// message is not evidence that the proxy refused the exchange.
func requireWSCloseCode(t *testing.T, conn net.Conn, want ws.StatusCode) {
	t.Helper()
	if err := wsCloseEvidence(conn, want, testwait.Deadline(10*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func wsCloseEvidence(conn net.Conn, want ws.StatusCode, wait time.Duration) error {
	// ReadServerData answers a Close with its own Close, so bound the write too.
	_ = conn.SetDeadline(time.Now().Add(wait))
	msg, op, err := wsutil.ReadServerData(conn)
	var closed wsutil.ClosedError
	if !errors.As(err, &closed) {
		return fmt.Errorf("want WebSocket close %d, got op=%v msg=%q err=%T %w", want, op, msg, err, err)
	}
	if closed.Code != want {
		return fmt.Errorf("WebSocket close code = %d (%q), want %d", closed.Code, closed.Reason, want)
	}
	return nil
}

// The evidence check accepts only the expected Close. Everything else a block
// assertion used to accept must fail it.
func TestWSCloseEvidenceRejectsEverythingButTheExpectedClose(t *testing.T) {
	closeFrame := func(code ws.StatusCode) func(net.Conn) {
		return func(c net.Conn) {
			_ = ws.WriteFrame(c, ws.NewCloseFrame(ws.NewCloseFrameBody(code, "")))
			_, _ = io.Copy(io.Discard, c) // accept the client's Close reply
		}
	}
	for _, tc := range []struct {
		name    string
		server  func(net.Conn)
		wantErr string
	}{
		{name: "expected close", server: closeFrame(ws.StatusPolicyViolation)},
		{name: "other close code", server: closeFrame(ws.StatusNormalClosure), wantErr: "close code = 1000"},
		{name: "bare disconnect", server: func(c net.Conn) { _ = c.Close() }, wantErr: "want WebSocket close"},
		{name: "silent until deadline", server: func(net.Conn) {}, wantErr: "want WebSocket close"},
		{name: "data message", server: func(c net.Conn) { _ = wsutil.WriteServerMessage(c, ws.OpText, []byte("forwarded")) }, wantErr: "want WebSocket close"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			go tc.server(server)
			err := wsCloseEvidence(client, ws.StatusPolicyViolation, 200*time.Millisecond)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected close rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
