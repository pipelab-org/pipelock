// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package cliutil

import "os"

func openVerifierFile(path string) (*os.File, error) {
	return openCheckedVerifierFile(path, os.O_RDONLY)
}
