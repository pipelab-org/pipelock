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

// UninspectedMessageChunkError marks bytes of a message beyond the inspection
// ceiling. Final includes the original newline, or the final bytes at EOF.
type UninspectedMessageChunkError struct {
	Final  bool
	Reason string
}

func (e *UninspectedMessageChunkError) Error() string {
	if e.Reason != "" {
		return e.Reason
	}
	return "message exceeds inspection ceiling"
}

// WatchStdioReader uses the ordinary message limit for inspection, but returns
// bounded chunks for byte-preserving forwarding when observation is enabled.
type WatchStdioReader struct {
	reader   *bufio.Reader
	enabled  func() bool
	draining bool
	limit    int
}

func NewWatchStdioReader(r io.Reader, enabled func() bool) *WatchStdioReader {
	return &WatchStdioReader{reader: bufio.NewReader(r), enabled: enabled, limit: MaxLineSize}
}

func (r *WatchStdioReader) ReadMessage() ([]byte, error) {
	if r.draining {
		chunk, err := r.reader.ReadSlice('\n')
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("reading message: %w", err)
		}
		final := !errors.Is(err, bufio.ErrBufferFull)
		r.draining = !final
		return append([]byte(nil), chunk...), &UninspectedMessageChunkError{Final: final}
	}
	var line []byte
	for {
		chunk, err := r.reader.ReadSlice('\n')
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("reading message: %w", err)
		}
		line = append(line, chunk...)
		if len(line) > r.limit {
			if r.enabled == nil || !r.enabled() {
				return nil, fmt.Errorf("reading message: %w", bufio.ErrTooLong)
			}
			final := !errors.Is(err, bufio.ErrBufferFull)
			r.draining = !final
			return line, &UninspectedMessageChunkError{Final: final}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(line) == 0 && errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		if r.enabled != nil && r.enabled() {
			// Only transport framing is removed. The writer supplies the delimiter.
			return bytes.TrimSuffix(line, []byte("\n")), nil
		}
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			return line, nil
		}
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
	}
}

// WithRawMessage lets a bounded forwarding loop preserve oversized message
// bytes without adding a newline after every chunk.
func (sw *StdioWriter) WithRawMessage(write func(io.Writer) error) error { return write(sw.w) }
