// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"fmt"
	"io"
)

// WatchBodyReader applies the inspection ceiling without limiting delivery.
// Oversized messages are streamed in bounded chunks, with one stdio delimiter.
type WatchBodyReader struct {
	Body          io.ReadCloser
	Uninspected   bool
	Reason        string
	started, done bool
}

func (r *WatchBodyReader) ReadMessage() ([]byte, error) {
	if r.done {
		return nil, io.EOF
	}
	limit := MaxLineSize + 1
	if r.started || r.Uninspected {
		limit = 32 * 1024
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)))
	if err != nil {
		_ = r.Body.Close()
		return nil, fmt.Errorf("%w: reading response body: %w", ErrIncompleteResponse, err)
	}
	final := len(data) < limit
	if !r.started && !r.Uninspected && len(data) <= MaxLineSize {
		r.done = true
		_ = r.Body.Close()
		if len(data) == 0 {
			return nil, io.EOF
		}
		return data, nil
	}
	r.started = true
	if final {
		r.done = true
		_ = r.Body.Close()
		data = append(data, '\n')
	}
	return data, &UninspectedMessageChunkError{Final: final, Reason: r.Reason}
}
func (r *WatchBodyReader) Close() error { return r.Body.Close() }

// StreamMessage permits transport bridges to send a bounded, already checked
// message stream without buffering it into a single allocation.
func (c *HTTPClient) SendStream(ctx context.Context, body io.Reader) (MessageReader, error) {
	return c.sendMessageReader(ctx, nil, body, HTTPMessageOptions{})
}
