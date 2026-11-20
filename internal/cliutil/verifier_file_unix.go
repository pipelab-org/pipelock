// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cliutil

import (
	"os"
	"syscall"
)

const verifierOpenFlags = os.O_RDONLY | syscall.O_NONBLOCK

// openVerifierFile checks the type before opening so a named pipe is refused
// without a reader, then opens without blocking and rechecks the opened file.
func openVerifierFile(path string) (*os.File, error) {
	if err := checkVerifierFileType(path); err != nil {
		return nil, err
	}
	return openCheckedVerifierFile(path, verifierOpenFlags)
}

func checkVerifierFileType(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errVerifierFileType
	}
	return nil
}
