// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/gobwas/ws"
)

type watchWireConn struct {
	net.Conn
	reader   io.Reader
	written  bytes.Buffer
	writeErr error
}

func (c *watchWireConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *watchWireConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.written.Write(p)
}

func watchFrameWire(t *testing.T, frames ...ws.Frame) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, frame := range frames {
		if err := ws.WriteFrame(&out, frame); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

func watchReadWire(t *testing.T, wire []byte) (*WSClient, *watchWireConn) {
	t.Helper()
	conn := &watchWireConn{reader: bytes.NewReader(wire)}
	c := NewWSClientFromConn(conn, false)
	c.WatchOnly = func() bool { return true }
	return c, conn
}

func watchDecodedFrames(t *testing.T, wire []byte) []ws.Frame {
	t.Helper()
	r := bytes.NewReader(wire)
	var frames []ws.Frame
	for r.Len() > 0 {
		h, err := ws.ReadHeader(r)
		if err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, int(h.Length))
		if _, err := io.ReadFull(r, payload); err != nil {
			t.Fatal(err)
		}
		if h.Masked {
			ws.Cipher(payload, h.Mask, 0)
		}
		frames = append(frames, ws.Frame{Header: h, Payload: payload})
	}
	return frames
}

func TestWatchWSFragmentsRetainControlAndMasking(t *testing.T) {
	wire := watchFrameWire(t,
		ws.MaskFrame(ws.NewFrame(ws.OpText, false, []byte("hel"))),
		ws.MaskFrame(ws.NewFrame(ws.OpPing, true, []byte("probe"))),
		ws.NewFrame(ws.OpPong, true, nil),
		ws.MaskFrame(ws.NewFrame(ws.OpContinuation, true, []byte("lo"))),
		ws.NewFrame(ws.OpText, true, []byte("next")),
		ws.NewFrame(ws.OpClose, true, nil))
	client, conn := watchReadWire(t, wire)
	for _, want := range []string{"hello", "next"} {
		msg, err := client.ReadMessage()
		if err != nil || string(msg) != want {
			t.Fatalf("message=%q want=%q err=%v", msg, want, err)
		}
	}
	if _, err := client.ReadMessage(); !errors.Is(err, io.EOF) {
		t.Fatalf("close=%v", err)
	}
	replies := watchDecodedFrames(t, conn.written.Bytes())
	if len(replies) != 1 || replies[0].Header.OpCode != ws.OpPong || !replies[0].Header.Masked || string(replies[0].Payload) != "probe" {
		t.Fatalf("ping reply=%+v", replies)
	}
}

func TestWatchWSUninspectedFramesPreserveBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frame  ws.Frame
		reason string
	}{
		{"binary", ws.NewFrame(ws.OpBinary, true, []byte{1, 2, 3}), "binary websocket message"},
		{"utf8", ws.NewFrame(ws.OpText, true, []byte{0xff, 0xfe}), "invalid UTF-8 websocket message"},
		{"extension", ws.Frame{Header: ws.Header{Fin: true, OpCode: ws.OpText, Rsv: 4, Length: 3}, Payload: []byte("zip")}, "websocket extension payload"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := watchReadWire(t, watchFrameWire(t, tc.frame))
			msg, err := client.ReadMessage()
			var chunk *UninspectedMessageChunkError
			if !errors.As(err, &chunk) || !chunk.Final || chunk.Reason != tc.reason || !bytes.Equal(msg, append(append([]byte(nil), tc.frame.Payload...), '\n')) {
				t.Fatalf("message=%q chunk=%+v err=%v", msg, chunk, err)
			}
			if _, err := client.ReadMessage(); !errors.Is(err, io.EOF) {
				t.Fatalf("stream end=%v", err)
			}
		})
	}
	data := bytes.Repeat([]byte("x"), 65537)
	client, _ := watchReadWire(t, watchFrameWire(t, ws.MaskFrame(ws.NewFrame(ws.OpBinary, false, data)), ws.NewFrame(ws.OpContinuation, true, []byte("tail"))))
	got, streamed := collectWatchMessage(t, client)
	if !streamed || !bytes.Equal(got, append(data, []byte("tail")...)) {
		t.Fatalf("fragmented binary changed: bytes=%d streamed=%v", len(got), streamed)
	}
}

func TestWatchWSMalformedOrInterruptedFramesFail(t *testing.T) {
	frame := func(op ws.OpCode, fin bool, payload string) ws.Frame { return ws.NewFrame(op, fin, []byte(payload)) }
	for _, tc := range []struct {
		name       string
		wire       []byte
		reason     string
		incomplete bool
	}{
		{"unexpected continuation", watchFrameWire(t, frame(ws.OpContinuation, true, "x")), "unexpected websocket continuation", false},
		{"new message during fragment", watchFrameWire(t, frame(ws.OpText, false, "x"), frame(ws.OpText, true, "y")), "new websocket message", false},
		{"unknown data", watchFrameWire(t, frame(ws.OpCode(3), true, "x")), "unknown websocket data", false},
		{"unknown control", watchFrameWire(t, frame(ws.OpCode(11), true, "")), "unknown websocket control", false},
		{"fragmented control", watchFrameWire(t, frame(ws.OpPing, false, "")), "malformed websocket control", false},
		{"long control", watchFrameWire(t, frame(ws.OpPing, true, strings.Repeat("x", 126))), "malformed websocket control", false},
		{"control payload interrupted", []byte{0x89, 0x02, 'x'}, "unexpected EOF", false},
		{"header interrupted", []byte{0x81}, "reading ws header", true},
		{"data interrupted", []byte{0x81, 0x02, 'x'}, "reading websocket payload", true},
		{"fragment interrupted", watchFrameWire(t, frame(ws.OpText, false, "x")), "reading ws header", true},
		{"close during fragment", watchFrameWire(t, frame(ws.OpText, false, "x"), frame(ws.OpClose, true, "")), "incomplete upstream response", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := watchReadWire(t, tc.wire)
			msg, err := client.ReadMessage()
			if err == nil || !strings.Contains(err.Error(), tc.reason) || len(msg) != 0 {
				t.Fatalf("malformed message released: %q error=%v", msg, err)
			}
			if tc.incomplete && !errors.Is(err, ErrIncompleteResponse) {
				t.Fatalf("interruption unclassified: %v", err)
			}
		})
	}
	// RFC 6455's high length bit is refused by the frame parser, before the
	// watch reader can receive a negative int64 payload length.
	invalidLength, _ := watchReadWire(t, []byte{0x81, 0x7f, 0x80, 0, 0, 0, 0, 0, 0, 0})
	if _, err := invalidLength.ReadMessage(); !errors.Is(err, ws.ErrHeaderLengthMSB) || !errors.Is(err, ErrIncompleteResponse) {
		t.Fatalf("invalid 64-bit payload length was not refused: %v", err)
	}
	client, conn := watchReadWire(t, watchFrameWire(t, frame(ws.OpPing, true, "ping")))
	failure := errors.New("pong unavailable")
	conn.writeErr = failure
	if _, err := client.ReadMessage(); !errors.Is(err, failure) {
		t.Fatalf("pong failure=%v", err)
	}
}

func TestWatchWSRawMessagePreservesFraming(t *testing.T) {
	for _, server := range []bool{false, true} {
		for _, chunks := range [][]string{{"a", "bc", "\n"}, {"abc"}, {"\n"}, {"", "abc\n"}} {
			conn := &watchWireConn{}
			client := NewWSClientFromConn(conn, server)
			err := client.WithRawMessage(func(w io.Writer) error {
				for _, chunk := range chunks {
					n, err := w.Write([]byte(chunk))
					if err != nil {
						return err
					}
					if n != len(chunk) {
						return io.ErrShortWrite
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			frames := watchDecodedFrames(t, conn.written.Bytes())
			var got bytes.Buffer
			for i, frame := range frames {
				wantOp := ws.OpContinuation
				if i == 0 {
					wantOp = ws.OpText
				}
				if frame.Header.OpCode != wantOp || frame.Header.Masked == server || frame.Header.Fin != (i == len(frames)-1) {
					t.Fatalf("fragment %d has wrong metadata: %+v", i, frame.Header)
				}
				_, _ = got.Write(frame.Payload)
			}
			want := strings.TrimSuffix(strings.Join(chunks, ""), "\n")
			if len(frames) == 0 || got.String() != want {
				t.Fatalf("raw message=%q want=%q", got.String(), want)
			}
		}
	}
}

func TestWatchWSRawMessageWriteFailuresStop(t *testing.T) {
	failure := errors.New("downstream write failed")
	for _, where := range []string{"callback", "pending", "payload", "tail", "final"} {
		t.Run(where, func(t *testing.T) {
			conn := &watchWireConn{}
			client := NewWSClientFromConn(conn, true)
			err := client.WithRawMessage(func(w io.Writer) error {
				switch where {
				case "callback":
					return failure
				case "pending":
					if _, err := w.Write([]byte("a")); err != nil {
						return err
					}
					conn.writeErr = failure
					_, err := w.Write([]byte("b"))
					return err
				case "payload":
					conn.writeErr = failure
					_, err := w.Write([]byte("abc"))
					return err
				case "tail":
					if _, err := w.Write([]byte("a")); err != nil {
						return err
					}
					conn.writeErr = failure
					return nil
				default:
					conn.writeErr = failure
					return nil
				}
			})
			if !errors.Is(err, failure) || conn.written.Len() != 0 {
				t.Fatalf("failed write delivered bytes=%d err=%v", conn.written.Len(), err)
			}
		})
	}
}
