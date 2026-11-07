// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func (sw *syncWriter) WithRawMessage(write func(io.Writer) error) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return write(sw.w)
}

func forwardWatchUninspected(first []byte, firstErr error, reader transport.MessageReader, writer transport.MessageWriter, opts MCPProxyOpts) error {
	if !opts.watchInbound {
		opts.recordWatch("mcp_protocol", "outbound message exceeds inspection ceiling", config.ActionBlock, 0, true)
		return errors.New("outbound inspection limit enforced in watch-only")
	}
	raw, ok := writer.(interface {
		WithRawMessage(func(io.Writer) error) error
	})
	if !ok {
		return errors.New("transport cannot stream an oversized message")
	}
	return raw.WithRawMessage(func(w io.Writer) error {
		chunk, err := first, firstErr
		tail := ""
		for {
			var part *transport.UninspectedMessageChunkError
			if !errors.As(err, &part) {
				return fmt.Errorf("reading uninspected message: %w", err)
			}
			if opts.KillSwitch != nil && opts.KillSwitch.IsActive() {
				opts.recordWatch("kill_switch", "operator kill switch", config.ActionBlock, 0, true)
				return errors.New("kill switch enforced in watch-only")
			}
			// The existing SSE rolling-window bound also bounds this opportunistic
			// floor scan. Structured/encoded whole-message coverage is uninspected.
			if sc := opts.scanner(); !opts.watchInbound && sc != nil && watchCoreMatches(sc.ScanTextForDLP(opts.warnContext(), tail+string(chunk)).Matches) {
				opts.recordWatch("dlp", "core credential floor", config.ActionBlock, 0, true)
				return errors.New("core credential floor enforced in watch-only")
			}
			combined := append([]byte(tail), chunk...)
			tail = ""
			if !part.Final {
				tail = advanceSSERollingTail("", combined, false, "")
				combined = combined[:len(combined)-len(tail)]
			}
			n, writeErr := w.Write(combined)
			opts.recordWatch("mcp_protocol", part.Error(), "uninspected", int64(n), false)
			if writeErr != nil {
				return fmt.Errorf("forwarding uninspected message: %w", writeErr)
			}
			if n != len(combined) {
				return io.ErrShortWrite
			}
			if part.Final {
				return nil
			}
			chunk, err = reader.ReadMessage()
		}
	})
}
