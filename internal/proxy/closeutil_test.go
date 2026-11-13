// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
)

type closeErrCloser struct {
	err error
}

func (c closeErrCloser) Close() error { return c.err }

func TestSafeCloseSkipsAlreadyClosed(t *testing.T) {
	other := errors.New("disk full")
	tests := []struct {
		name    string
		closer  io.Closer
		nilLog  bool
		wantLog bool
		wantSub string
	}{
		{name: "net closed", closer: closeErrCloser{err: net.ErrClosed}},
		{name: "wrapped net closed", closer: closeErrCloser{err: fmt.Errorf("relay: %w", net.ErrClosed)}},
		{name: "os closed", closer: closeErrCloser{err: os.ErrClosed}},
		{name: "wrapped os closed", closer: closeErrCloser{err: fmt.Errorf("file: %w", os.ErrClosed)}},
		{name: "other error", closer: closeErrCloser{err: other}, wantLog: true, wantSub: "disk full"},
		{name: "nil closer"},
		{name: "nil logger", closer: closeErrCloser{err: other}, nilLog: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			var logger *audit.Logger
			if !tt.nilLog {
				var err error
				logger, err = audit.NewWithStream("json", "stdout", "", true, true, &logs)
				if err != nil {
					t.Fatalf("logger: %v", err)
				}
				t.Cleanup(func() { logger.Close() })
			}
			safeClose(tt.closer, "targetConn", logger)
			got := logs.String()
			if tt.wantLog {
				if !strings.Contains(got, `"event":"error"`) || !strings.Contains(got, tt.wantSub) {
					t.Fatalf("log = %q, want an error containing %q", got, tt.wantSub)
				}
				return
			}
			if strings.Contains(got, `"event":"error"`) {
				t.Fatalf("already-closed or inert close was logged: %s", got)
			}
		})
	}
}
