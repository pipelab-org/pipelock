// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package checker

import (
	"errors"
	"net"
)

// PeerUID fails closed where peer credentials are unsupported.
func PeerUID(_ uint32) func(net.Conn) error {
	return func(net.Conn) error { return errors.New("checker peer verification unsupported") }
}
