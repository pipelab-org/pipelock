// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/audit"
)

// safeClose calls Close on c and logs any error via the audit logger.
// The label identifies the resource in log messages (e.g. "targetConn",
// "resp.Body"). If logger is nil, errors are silently discarded.
//
// Use this instead of bare close-and-ignore patterns in proxy code so close
// failures are observable in audit logs. Closing a connection or file that
// is already closed is the normal end of a relay, so those sentinels are
// not audit errors. Every other close error is still logged.
func safeClose(c io.Closer, label string, logger *audit.Logger) {
	if c == nil {
		return
	}
	err := c.Close()
	if err == nil || logger == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return
	}
	logger.LogError(audit.NewMethodLogContext("close"), fmt.Errorf("%s: %w", label, err))
}
