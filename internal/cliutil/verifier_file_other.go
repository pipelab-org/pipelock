// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package cliutil

import "os"

func openVerifierFile(root *os.Root, name string) (*os.File, error) {
	return openCheckedVerifierFile(root, name, os.O_RDONLY)
}
