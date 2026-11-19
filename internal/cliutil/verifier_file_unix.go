// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cliutil

import (
	"os"
	"syscall"
)

const verifierOpenFlags = os.O_RDONLY | syscall.O_NONBLOCK

func openVerifierFile(root *os.Root, name string) (*os.File, error) {
	if err := checkVerifierFileType(root, name); err != nil {
		return nil, err
	}
	return openCheckedVerifierFile(root, name, verifierOpenFlags)
}

func checkVerifierFileType(root *os.Root, name string) error {
	info, err := root.Stat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errVerifierFileType
	}
	return nil
}
