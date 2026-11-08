// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// watchSSEReader retains the origin's framing. Its buffer is bounded by the
// configured inspection ceiling; an event beyond that ceiling streams through
// onUninspected without allocating memory proportional to the event.
type watchSSEReader struct {
	reader        *bufio.Reader
	limit         int
	wire          []byte
	uninspected   bool
	onUninspected func([]byte) error
	// payload is the size of the current event's data payload, data lines
	// joined by one newline each, counted while the event streams. Wire size
	// also covers comments and other fields, so it cannot stand in for it.
	payload   int
	dataLines int
}

// NewWatchSSEReader preserves original SSE bytes for observation-only delivery.
// onUninspected must forward and account for each supplied chunk before return.
func NewWatchSSEReader(r io.Reader, limit int, onUninspected func([]byte) error) *SSEReader {
	if limit <= 0 {
		limit = MaxLineSize
	}
	return &SSEReader{watch: &watchSSEReader{reader: bufio.NewReader(r), limit: limit, onUninspected: onUninspected}}
}

// RawMessage is the complete current event, including comments and line endings.
// It is empty when the current event was streamed through onUninspected.
func (sr *SSEReader) RawMessage() []byte {
	if sr.watch == nil {
		return nil
	}
	return sr.watch.wire
}

// PayloadBytes is the current event's data payload size as the scanner would
// join it. It is tracked while streaming, so the size of an event beyond the
// inspection ceiling is known without buffering it.
func (sr *SSEReader) PayloadBytes() int {
	if sr.watch == nil {
		return 0
	}
	return sr.watch.payload
}

func trimSSEEOL(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

// countPayload adds a chunk of a data line to the payload size. A chunk that
// starts a line carries the field name; later chunks continue the line.
func (wr *watchSSEReader) countPayload(chunk []byte, startsLine bool, inData *bool) {
	if startsLine {
		*inData = bytes.HasPrefix(chunk, []byte("data:"))
		if !*inData {
			return
		}
		if wr.dataLines > 0 {
			wr.payload++
		}
		wr.dataLines++
		chunk = bytes.TrimPrefix(chunk[len("data:"):], []byte(" "))
	} else if !*inData {
		return
	}
	wr.payload += len(trimSSEEOL(chunk))
}

// Uninspected reports an event streamed beyond the inspection memory ceiling.
func (sr *SSEReader) Uninspected() bool { return sr.watch != nil && sr.watch.uninspected }

func (sr *SSEReader) readWatchMessage() ([]byte, error) {
	wr := sr.watch
	wr.wire = wr.wire[:0]
	wr.uninspected = false
	wr.payload, wr.dataLines = 0, 0
	sr.lastEventType, sr.lastRetry = "", ""
	lineStarted, inData := false, false
	for {
		chunk, err := wr.reader.ReadSlice('\n')
		wr.countPayload(chunk, !lineStarted, &inData)
		boundary := !lineStarted && (bytes.Equal(chunk, []byte("\n")) || bytes.Equal(chunk, []byte("\r\n")))
		if !wr.uninspected && len(wr.wire)+len(chunk) > wr.limit {
			wr.uninspected = true
			if wr.onUninspected == nil {
				return nil, errors.New("watch-only SSE passthrough callback missing")
			}
			if len(wr.wire) != 0 {
				if writeErr := wr.onUninspected(wr.wire); writeErr != nil {
					return nil, fmt.Errorf("forwarding uninspected SSE: %w", writeErr)
				}
				wr.wire = wr.wire[:0]
			}
		}
		if wr.uninspected {
			if len(chunk) != 0 {
				if writeErr := wr.onUninspected(chunk); writeErr != nil {
					return nil, fmt.Errorf("forwarding uninspected SSE: %w", writeErr)
				}
			}
		} else {
			wr.wire = append(wr.wire, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			lineStarted = true
			continue
		}
		lineStarted = false
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("reading SSE: %w", err)
		}
		if boundary || errors.Is(err, io.EOF) {
			if len(wr.wire) == 0 && !wr.uninspected && errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
			if wr.uninspected {
				return nil, nil
			}
			return sr.parseWatchEvent(), nil
		}
	}
}

func (sr *SSEReader) parseWatchEvent() []byte {
	var data []string
	for _, raw := range bytes.Split(sr.watch.wire, []byte("\n")) {
		line := strings.TrimSuffix(string(raw), "\r")
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "data":
			data = append(data, value)
		case "id":
			if !strings.ContainsRune(value, 0) {
				sr.lastEventID = value
			}
		case "event":
			sr.lastEventType = value
		case "retry":
			sr.lastRetry = value
		}
	}
	return []byte(strings.Join(data, "\n"))
}
