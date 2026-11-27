// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
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

// requireWSEndWithoutData requires the connection to end before the deadline
// with nothing delivered: a bare EOF, or a Close carrying allowed. Any other
// Close code, a data message or a deadline fails.
func requireWSEndWithoutData(t *testing.T, conn net.Conn, allowed ws.StatusCode) {
	t.Helper()
	if err := wsEndEvidence(conn, allowed, testwait.Deadline(10*time.Second)); err != nil {
		t.Fatal(err)
	}
}

// wsServerEnd is what ended a server stream: a Close frame (closed true) or a
// read error. Control frames before it are skipped; a data frame is reported.
type wsServerEnd struct {
	closed bool
	code   ws.StatusCode
	reason string
	data   *ws.Header
	err    error
}

// readWSServerEnd reads server frames without answering them. Validating a
// received Close must not depend on writing the Close reply, which fails when
// the peer closes right after sending its own. ws.ReadFrame does not enforce
// RFC 6455 frame rules, so each header is checked before a control frame is
// skipped: an oversized, fragmented or masked server frame is an error, not
// something to step over on the way to EOF.
func readWSServerEnd(conn net.Conn, wait time.Duration) wsServerEnd {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	reader := io.LimitedReader{R: conn}
	for {
		reader.N = ws.MaxHeaderSize
		header, err := ws.ReadHeader(&reader)
		if err != nil {
			// ReadHeader may see EOF on a later read within the same header.
			if errors.Is(err, io.EOF) && reader.N < ws.MaxHeaderSize {
				err = io.ErrUnexpectedEOF
			}
			return wsServerEnd{err: err}
		}
		// Check the header before reading its payload: a peer that sends an
		// oversized header and disconnects must not end as a clean EOF.
		if err := ws.CheckHeader(header, ws.StateClientSide); err != nil {
			return wsServerEnd{err: fmt.Errorf("server sent an invalid frame (op=%v len=%d): %w", header.OpCode, header.Length, err)}
		}
		if !header.OpCode.IsControl() {
			return wsServerEnd{data: &header}
		}
		// CheckHeader limits control payloads to ws.MaxControlFramePayloadSize.
		payload := make([]byte, header.Length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			// A frame cut off mid-payload is a truncated frame, never a clean end.
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return wsServerEnd{err: fmt.Errorf("frame payload (op=%v len=%d): %w", header.OpCode, header.Length, err)}
		}
		if header.OpCode != ws.OpClose {
			continue
		}
		switch len(payload) {
		case 0:
			return wsServerEnd{closed: true}
		case 1:
			return wsServerEnd{err: fmt.Errorf("close frame status: %w", io.ErrUnexpectedEOF)}
		}
		code, reason := ws.ParseCloseFrameData(payload)
		if err := ws.CheckCloseFrameData(code, reason); err != nil {
			return wsServerEnd{err: fmt.Errorf("invalid close payload: %w", err)}
		}
		return wsServerEnd{closed: true, code: code, reason: reason}
	}
}

func wsCloseEvidence(conn net.Conn, want ws.StatusCode, wait time.Duration) error {
	end := readWSServerEnd(conn, wait)
	switch {
	case end.data != nil:
		return fmt.Errorf("want WebSocket close %d, got a data frame (op=%v)", want, end.data.OpCode)
	case !end.closed:
		return fmt.Errorf("want WebSocket close %d, got err=%T %w", want, end.err, end.err)
	case end.code != want:
		return fmt.Errorf("WebSocket close code = %d (%q), want %d", end.code, end.reason, want)
	}
	return nil
}

func wsEndEvidence(conn net.Conn, allowed ws.StatusCode, wait time.Duration) error {
	end := readWSServerEnd(conn, wait)
	switch {
	case end.data != nil:
		return fmt.Errorf("want the connection to end without data, got a data frame (op=%v)", end.data.OpCode)
	case end.closed && end.code != allowed:
		return fmt.Errorf("WebSocket close code = %d (%q), want EOF or %d", end.code, end.reason, allowed)
	case !end.closed && !errors.Is(end.err, io.EOF):
		return fmt.Errorf("want EOF or WebSocket close %d, got err=%T %w", allowed, end.err, end.err)
	}
	return nil
}

// wsTestCloseThenDisconnect sends one Close and disconnects without reading
// the reply.
func wsTestCloseThenDisconnect(code ws.StatusCode) func(net.Conn) {
	return func(c net.Conn) {
		_ = ws.WriteFrame(c, ws.NewCloseFrame(ws.NewCloseFrameBody(code, "")))
		_ = c.Close()
	}
}

// wsTestWriteFrameHeaderOnly writes a frame header announcing a payload and
// none of the payload.
func wsTestWriteFrameHeaderOnly(c net.Conn, op ws.OpCode, length int64) {
	_ = ws.WriteHeader(c, ws.Header{Fin: true, OpCode: op, Length: length})
}

// wsTestWriteOversizedPing writes a Ping with a 200-byte payload, past the
// 125 bytes RFC 6455 allows a control frame. ws.WriteFrame does not refuse it.
func wsTestWriteOversizedPing(c net.Conn) {
	_ = ws.WriteFrame(c, ws.NewPingFrame(make([]byte, 200)))
}

func runWSEvidenceCase(t *testing.T, server func(net.Conn), check func(net.Conn) error, wantErr string) {
	t.Helper()
	client, srv := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = srv.Close() })
	go server(srv)
	err := check(client)
	if wantErr == "" {
		if err != nil {
			t.Fatalf("expected outcome rejected: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("err = %v, want it to contain %q", err, wantErr)
	}
}

func TestWSServerEndLeavesUnexpectedDataPayloadUnread(t *testing.T) {
	var input bytes.Buffer
	payload := []byte("x")
	if err := ws.WriteFrame(&input, ws.NewBinaryFrame(payload)); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	end := readWSServerEnd(readerConn{Reader: &input, Conn: client}, time.Second)
	if end.data == nil || end.data.OpCode != ws.OpBinary {
		t.Fatalf("expected binary data evidence, got %+v", end)
	}
	if got := input.Len(); got != len(payload) {
		t.Fatalf("unread payload bytes = %d, want %d", got, len(payload))
	}
}

func TestWSEndEvidenceRejectsPartialExtendedHeader(t *testing.T) {
	// RFC 6455 uses the extended length field for a 126-byte data frame.
	frame := ws.NewBinaryFrame(make([]byte, 126))
	input := io.LimitReader(wsWire(t, frame), 2)
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	conn := readerConn{Reader: input, Conn: client}

	if err := wsEndEvidence(conn, ws.StatusProtocolError, time.Second); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want unexpected EOF", err)
	}
}

func TestWSCloseEvidenceValidatesPayload(t *testing.T) {
	const status = ws.StatusPolicyViolation
	payload := ws.NewCloseFrameBody(status, "é")
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	for _, tc := range []struct {
		name    string
		payload []byte
		want    ws.StatusCode
		wantErr error
	}{
		{name: "empty payload"},
		{name: "complete reason", payload: payload, want: status},
		{name: "partial reason", payload: payload[:len(payload)-1], want: status, wantErr: ws.ErrProtocolInvalidUTF8},
		{name: "partial status", payload: payload[:1], wantErr: io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := readerConn{Reader: wsWire(t, ws.NewCloseFrame(tc.payload)), Conn: client}
			if err := wsCloseEvidence(conn, tc.want, time.Second); !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// The evidence check accepts only the expected Close, including one the peer
// sends just before disconnecting. Everything else a block assertion used to
// accept must fail it.
func TestWSCloseEvidenceRejectsEverythingButTheExpectedClose(t *testing.T) {
	check := func(c net.Conn) error { return wsCloseEvidence(c, ws.StatusPolicyViolation, 200*time.Millisecond) }
	for _, tc := range []struct {
		name    string
		server  func(net.Conn)
		wantErr string
	}{
		{name: "expected close", server: wsTestCloseThenDisconnect(ws.StatusPolicyViolation)},
		{name: "expected close after ping", server: func(c net.Conn) {
			_ = ws.WriteFrame(c, ws.NewPingFrame([]byte("p")))
			wsTestCloseThenDisconnect(ws.StatusPolicyViolation)(c)
		}},
		{name: "other close code", server: wsTestCloseThenDisconnect(ws.StatusNormalClosure), wantErr: "close code = 1000"},
		{name: "bare disconnect", server: func(c net.Conn) { _ = c.Close() }, wantErr: "want WebSocket close"},
		{name: "silent until deadline", server: func(net.Conn) {}, wantErr: "want WebSocket close"},
		{name: "data message", server: func(c net.Conn) { _ = wsutil.WriteServerMessage(c, ws.OpText, []byte("forwarded")) }, wantErr: "got a data frame"},
		{name: "oversized ping before the close", server: func(c net.Conn) {
			wsTestWriteOversizedPing(c)
			wsTestCloseThenDisconnect(ws.StatusPolicyViolation)(c)
		}, wantErr: "invalid frame"},
	} {
		t.Run(tc.name, func(t *testing.T) { runWSEvidenceCase(t, tc.server, check, tc.wantErr) })
	}
}

// The end-without-data check accepts a bare EOF or the one allowed Close code
// and rejects any other Close, delivered data and a deadline.
func TestWSEndEvidenceAcceptsOnlyEOFOrTheAllowedClose(t *testing.T) {
	check := func(c net.Conn) error { return wsEndEvidence(c, ws.StatusProtocolError, 200*time.Millisecond) }
	for _, tc := range []struct {
		name    string
		server  func(net.Conn)
		wantErr string
	}{
		{name: "bare disconnect", server: func(c net.Conn) { _ = c.Close() }},
		{name: "allowed close", server: wsTestCloseThenDisconnect(ws.StatusProtocolError)},
		{name: "other close code", server: wsTestCloseThenDisconnect(ws.StatusPolicyViolation), wantErr: "want EOF or 1002"},
		{name: "silent until deadline", server: func(net.Conn) {}, wantErr: "want EOF or WebSocket close 1002"},
		{name: "data message", server: func(c net.Conn) { _ = wsutil.WriteServerMessage(c, ws.OpText, []byte("forwarded")) }, wantErr: "got a data frame"},
		{name: "oversized ping header then disconnect", server: func(c net.Conn) {
			wsTestWriteFrameHeaderOnly(c, ws.OpPing, 200)
			_ = c.Close()
		}, wantErr: "invalid frame"},
		{name: "truncated valid ping then disconnect", server: func(c net.Conn) {
			wsTestWriteFrameHeaderOnly(c, ws.OpPing, 4)
			_ = c.Close()
		}, wantErr: "unexpected EOF"},
		{name: "oversized ping then disconnect", server: func(c net.Conn) {
			wsTestWriteOversizedPing(c)
			_ = c.Close()
		}, wantErr: "invalid frame"},
	} {
		t.Run(tc.name, func(t *testing.T) { runWSEvidenceCase(t, tc.server, check, tc.wantErr) })
	}
}
