// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package checker

import (
	"errors"
	"net"
)

// PeerUID verifies the operating system's Unix socket peer credentials.
func PeerUID(uid uint32) func(net.Conn) error {
	return func(conn net.Conn) error {
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			return errors.New("checker peer is not a Unix socket")
		}
		raw, err := uc.SyscallConn()
		if err != nil {
			return errors.New("checker peer credentials unavailable")
		}
		var got uint32
		var peerErr error
		if err := raw.Control(func(fd uintptr) { got, peerErr = socketPeerUID(int(fd)) }); err != nil || peerErr != nil || got != uid {
			return errors.New("checker peer verification failed")
		}
		return nil
	}
}
