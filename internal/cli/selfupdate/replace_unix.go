// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package selfupdate

import (
	"fmt"
	"io"
	"os"
)

func replaceBinary(tmpPath, target string) error {
	if err := os.Rename(tmpPath, target); err != nil {
		return fmt.Errorf("original unchanged: %w", err)
	}
	return nil
}

// CleanupOnStart is a no-op on systems that can replace a running executable.
func CleanupOnStart(_ io.Writer) {}
