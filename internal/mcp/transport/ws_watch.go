// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/gobwas/ws"
)

type watchWSState struct {
	active, streaming, uninspected bool
	reason                         string
	header                         *ws.Header
	remaining                      int64
	offset                         int
	data                           []byte
}

func (c *WSClient) readWatchMessage() ([]byte, error) {
	s := &c.watchState
	for {
		if s.header == nil {
			hdr, err := ws.ReadHeader(c.r)
			if err != nil {
				if !s.active && errors.Is(err, io.EOF) {
					return nil, io.EOF
				}
				return nil, fmt.Errorf("%w: reading ws header: %w", ErrIncompleteResponse, err)
			}
			if hdr.OpCode.IsControl() {
				if !hdr.Fin || hdr.Length > 125 {
					return nil, errors.New("malformed websocket control frame")
				}
				payload := make([]byte, int(hdr.Length))
				if _, err = io.ReadFull(c.r, payload); err != nil {
					return nil, err
				}
				if hdr.Masked {
					ws.Cipher(payload, hdr.Mask, 0)
				}
				switch hdr.OpCode {
				case ws.OpClose:
					if s.active {
						return nil, ErrIncompleteResponse
					}
					return nil, io.EOF
				case ws.OpPing:
					c.writeMu.Lock()
					err = c.writeMsg(ws.OpPong, payload)
					c.writeMu.Unlock()
					if err != nil {
						return nil, err
					}
				case ws.OpPong:
				default:
					return nil, errors.New("unknown websocket control opcode")
				}
				continue
			}
			switch hdr.OpCode {
			case ws.OpText, ws.OpBinary:
				if s.active {
					return nil, errors.New("new websocket message during fragmented message")
				}
				s.active = true
				s.uninspected = hdr.OpCode == ws.OpBinary
				if s.uninspected {
					s.reason = "binary websocket message"
				}
			case ws.OpContinuation:
				if !s.active {
					return nil, errors.New("unexpected websocket continuation")
				}
			default:
				return nil, errors.New("unknown websocket data opcode")
			}
			if hdr.Length < 0 {
				return nil, errors.New("invalid websocket payload length")
			}
			if hdr.Rsv != 0 {
				s.uninspected = true
				s.reason = "websocket extension payload"
			}
			s.header = &hdr
			s.remaining = hdr.Length
			s.offset = 0
		}
		n := int64(32 * 1024)
		if s.remaining < n {
			n = s.remaining
		}
		payload := make([]byte, int(n))
		if _, err := io.ReadFull(c.r, payload); err != nil {
			return nil, fmt.Errorf("%w: reading websocket payload: %w", ErrIncompleteResponse, err)
		}
		if s.header.Masked {
			ws.Cipher(payload, s.header.Mask, s.offset)
		}
		s.offset += len(payload)
		s.remaining -= n
		s.data = append(s.data, payload...)
		final := s.remaining == 0 && s.header.Fin
		if s.remaining == 0 {
			s.header = nil
		}
		if final {
			data := s.data
			uninspected := s.streaming || s.uninspected || len(data) > MaxLineSize || !utf8.Valid(data)
			reason := s.reason
			if !utf8.Valid(data) && !s.streaming {
				reason = "invalid UTF-8 websocket message"
			}
			*s = watchWSState{}
			if uninspected {
				return append(data, '\n'), &UninspectedMessageChunkError{Final: true, Reason: reason}
			}
			return data, nil
		}
		if len(s.data) > MaxLineSize || s.streaming || s.uninspected {
			s.streaming = true
			data := s.data
			s.data = nil
			return data, &UninspectedMessageChunkError{Reason: s.reason}
		}
	}
}

// WithRawMessage preserves one stdio message as a fragmented text message.
// The stdio delimiter is consumed, never emitted as a separate WS message.
func (c *WSClient) WithRawMessage(write func(io.Writer) error) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	w := watchWSWriter{client: c, opcode: ws.OpText}
	if err := write(&w); err != nil {
		return err
	}
	if len(w.pending) > 0 && w.pending[0] != '\n' {
		if err := w.frame(w.pending, false); err != nil {
			return err
		}
	}
	return w.frame(nil, true)
}

type watchWSWriter struct {
	client  *WSClient
	opcode  ws.OpCode
	pending []byte
}

func (w *watchWSWriter) frame(p []byte, final bool) error {
	frame := ws.NewFrame(w.opcode, final, p)
	if !w.client.isServer {
		frame = ws.MaskFrame(frame)
	}
	if err := ws.WriteFrame(w.client.conn, frame); err != nil {
		return err
	}
	w.opcode = ws.OpContinuation
	return nil
}

func (w *watchWSWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(w.pending) > 0 {
		if err := w.frame(w.pending, false); err != nil {
			return 0, err
		}
	}
	if len(p) > 1 {
		if err := w.frame(p[:len(p)-1], false); err != nil {
			return 0, err
		}
	}
	w.pending = append(w.pending[:0], p[len(p)-1])
	return len(p), nil
}
