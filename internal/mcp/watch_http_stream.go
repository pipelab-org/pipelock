// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

type watchSpoolWriter struct{ io.Writer }

func (w watchSpoolWriter) WriteMessage(msg []byte) error { _, err := w.Write(msg); return err }

func (w watchSpoolWriter) WithRawMessage(write func(io.Writer) error) error { return write(w.Writer) }

func forwardWatchHTTPInput(ctx context.Context, first []byte, firstErr error, reader transport.MessageReader, client *transport.HTTPClient, output transport.MessageWriter, log io.Writer, opts MCPProxyOpts) error {
	if opts.AuthorityVerifier != nil {
		opts.recordWatch("authority", "oversized request cannot verify external grant", config.ActionBlock, 0, true)
		return errors.New("external action grant required in watch-only")
	}
	file, err := os.CreateTemp("", "pipelock-watch-message-*")
	if err != nil {
		return err
	}
	defer func() { _ = file.Close(); _ = os.Remove(file.Name()) }()
	if err = forwardWatchUninspected(first, firstErr, watchContextMessageReader{ctx, reader}, watchSpoolWriter{file}, opts); err != nil {
		return err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	response, err := client.SendStream(ctx, file)
	if err != nil {
		return err
	}
	_, err = ForwardScanned(response, output, log, nil, opts)
	return err
}

// Cancellation follows the bridge's existing non-closable-reader contract:
// at most one read may outlive cancellation; its buffered result cannot block.
type watchContextMessageReader struct {
	ctx    context.Context
	reader transport.MessageReader
}

func (r watchContextMessageReader) ReadMessage() ([]byte, error) {
	return readMCPInputMessage(r.ctx, nil, r.reader)
}
