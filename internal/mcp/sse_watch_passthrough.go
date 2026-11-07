// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func passthroughWatchSSE(ctx context.Context, body io.Reader, w io.Writer, flusher http.Flusher, _ *scanner.Scanner, opts GenericSSEScanOptions) error {
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
