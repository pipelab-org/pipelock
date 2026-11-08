// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func passthroughWatchSSE(ctx context.Context, body io.Reader, w io.Writer, flusher http.Flusher, _ *scanner.Scanner, opts GenericSSEScanOptions) error {
	if opts.WatchEvent != nil {
		return passthroughWatchEvents(ctx, body, w, flusher, opts)
	}
	var buf [32 * 1024]byte
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := body.Read(buf[:])
		if n > 0 {
			written, writeErr := w.Write(buf[:n])
			if opts.OnWatchOnly != nil {
				opts.OnWatchOnly("sse", "SSE inspection disabled", "uninspected", int64(written), false)
			}
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// Protocol inspection remains active when the generic text scanner is disabled.
func passthroughWatchEvents(ctx context.Context, body io.Reader, w io.Writer, flusher http.Flusher, opts GenericSSEScanOptions) error {
	write := func(raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := w.Write(raw)
		if opts.OnWatchOnly != nil {
			opts.OnWatchOnly("sse", "SSE inspection disabled", "uninspected", int64(n), false)
		}
		if err != nil {
			return err
		}
		if n != len(raw) {
			return io.ErrShortWrite
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	reader := transport.NewWatchSSEReader(body, DefaultGenericSSEMaxEventBytes, write)
	for {
		event, err := reader.ReadMessage()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if reader.Uninspected() {
			continue
		}
		if len(event) != 0 {
			if err := opts.WatchEvent(event); err != nil {
				return err
			}
		}
		if err := write(reader.RawMessage()); err != nil {
			return err
		}
		if opts.WatchEventDelivered != nil {
			opts.WatchEventDelivered()
		}
	}
}
