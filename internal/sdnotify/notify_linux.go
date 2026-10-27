// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sdnotify

import (
	"fmt"
	"net"
	"os"
	"time"
)

// Send sends a message using the protocol documented by sd_notify(3) and
// systemd.service(5). It deliberately has no dependency on go-systemd.
func Send(state string) (bool, error) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return false, nil
	}

	dialer := net.Dialer{Timeout: 100 * time.Millisecond}
	conn, err := dialer.Dial("unixgram", socket)
	if err != nil {
		return false, fmt.Errorf("dial NOTIFY_SOCKET: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return false, fmt.Errorf("set NOTIFY_SOCKET deadline: %w", err)
	}
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, fmt.Errorf("write NOTIFY_SOCKET: %w", err)
	}
	return true, nil
}
