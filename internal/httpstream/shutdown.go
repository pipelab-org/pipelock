// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"context"
	"errors"
)

// ErrShutdownIncomplete means a listener failed to drain before shutdown ended.
// Callers must not seal receipt chains as complete after this error.
var ErrShutdownIncomplete = errors.New("proxy shutdown incomplete")

// ServeUntilShutdown joins graceful shutdown after cancellation or a serve error.
// Serve can return before handlers finish; shutdown must drain or force-close
// them and return any drain failure before the caller seals receipt chains.
func ServeUntilShutdown(ctx context.Context, serve func() error, shutdown func() error) error {
	done := make(chan struct{})
	shutdownDone := make(chan struct{})
	var shutdownErr error
	go func() { //nolint:gosec // G118: graceful shutdown after <-ctx.Done(); using ctx as parent would skip the grace period
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
		case <-done:
		}
		shutdownErr = shutdown()
	}()
	err := serve()
	close(done)
	<-shutdownDone
	if shutdownErr != nil {
		return errors.Join(err, ErrShutdownIncomplete, shutdownErr)
	}
	return err
}
