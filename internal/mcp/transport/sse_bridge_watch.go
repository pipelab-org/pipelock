// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

// watchSSEBridgeReader removes only SSE framing when bridging to stdio. Data
// beyond the normal event ceiling is yielded incrementally rather than dropped.
type watchSSEBridgeReader struct {
	body                                           io.ReadCloser
	reader                                         *bufio.Reader
	data                                           []byte
	continued, dataLine, haveData, streaming, done bool
	pendingCR                                      bool
}

func newWatchSSEBridgeReader(body io.ReadCloser) *watchSSEBridgeReader {
	return &watchSSEBridgeReader{body: body, reader: bufio.NewReader(body)}
}
func (r *watchSSEBridgeReader) Close() error { return r.body.Close() }
func (r *watchSSEBridgeReader) ReadMessage() ([]byte, error) {
	if r.done {
		return nil, io.EOF
	}
	for {
		line, err := r.reader.ReadSlice('\n')
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) {
			_ = r.body.Close()
			return nil, fmt.Errorf("reading SSE: %w", err)
		}
		partial := errors.Is(err, bufio.ErrBufferFull)
		if r.pendingCR {
			if len(line) == 0 || line[0] != '\n' {
				line = append([]byte{'\r'}, line...)
			}
			r.pendingCR = false
		}
		if partial && len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
			r.pendingCR = true
		}
		boundary := !r.continued && (bytes.Equal(line, []byte("\n")) || bytes.Equal(line, []byte("\r\n")))
		if !partial {
			line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		}
		if !r.continued {
			r.dataLine = bytes.HasPrefix(line, []byte("data:")) || bytes.Equal(line, []byte("data"))
			if r.dataLine {
				if r.haveData {
					r.data = append(r.data, '\n')
				}
				r.haveData = true
				if bytes.HasPrefix(line, []byte("data:")) {
					line = bytes.TrimPrefix(line, []byte("data:"))
					line = bytes.TrimPrefix(line, []byte(" "))
				} else {
					line = nil
				}
			}
		}
		if r.dataLine && !boundary {
			r.data = append(r.data, line...)
		}
		r.continued = partial
		final := boundary || errors.Is(err, io.EOF)
		if final {
			r.done = errors.Is(err, io.EOF)
			if r.done {
				_ = r.body.Close()
			}
			if r.haveData {
				msg := r.data
				streamed := r.streaming
				r.data = nil
				r.haveData = false
				r.streaming = false
				r.dataLine = false
				if streamed {
					return append(msg, '\n'), &UninspectedMessageChunkError{Final: true}
				}
				return msg, nil
			}
			if r.done {
				return nil, io.EOF
			}
		}
		if len(r.data) > MaxLineSize || r.streaming && len(r.data) > 0 {
			r.streaming = true
			msg := r.data
			r.data = nil
			return msg, &UninspectedMessageChunkError{}
		}
	}
}
