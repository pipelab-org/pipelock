// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/luckyPipewrench/pipelock/internal/cliutil"

const maxVerifierInputBytes = cliutil.MaxVerifierInputBytes

func readVerifierFile(path string) ([]byte, error) {
	return cliutil.ReadVerifierFile(path)
}
