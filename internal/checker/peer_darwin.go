// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"errors"

	"golang.org/x/sys/unix"
)

func socketPeerUID(fd int) (uint32, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	if cred == nil {
		return 0, errors.New("checker peer credentials unavailable")
	}
	return cred.Uid, nil
}
