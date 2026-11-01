// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package wsutil

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gobwas/ws"
)

type projectingConn struct {
	net.Conn
}

func (projectingConn) ProjectCloseFrame(ws.StatusCode, string) (ws.StatusCode, string) {
	return ws.StatusPolicyViolation, "projected"
}

func TestCloseFrameWritersApplyProjector(t *testing.T) {
	writers := map[string]func(net.Conn, ws.StatusCode, string){
		"server": WriteCloseFrame,
		"client": WriteClientCloseFrame,
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			defer func() { _ = server.Close() }()
			defer func() { _ = client.Close() }()

			done := make(chan ws.Frame, 1)
			go func() {
				_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
				frame, err := ws.ReadFrame(server)
				if err != nil {
					done <- ws.Frame{}
					return
				}
				done <- ws.UnmaskFrameInPlace(frame)
			}()

			write(projectingConn{Conn: client}, ws.StatusNormalClosure, "detector reason")

			frame := <-done
			if frame.Header.OpCode != ws.OpClose || len(frame.Payload) < 2 {
				t.Fatalf("close frame = %+v", frame.Header)
			}
			if code := ws.StatusCode(binary.BigEndian.Uint16(frame.Payload[:2])); code != ws.StatusPolicyViolation {
				t.Fatalf("close code = %d, want projected %d", code, ws.StatusPolicyViolation)
			}
			if reason := frame.Payload[2:]; !bytes.Equal(reason, []byte("projected")) {
				t.Fatalf("close reason = %q, want projected", reason)
			}
		})
	}
}
