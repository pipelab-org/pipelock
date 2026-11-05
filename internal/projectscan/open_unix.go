// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package projectscan

import (
	"os"
	"path/filepath"
	"syscall"
)

// openNoBlock opens path read-only without blocking, so a FIFO swapped in for
// a candidate file cannot stall the scan while waiting for a writer.
func openNoBlock(path string) (*os.File, error) {
	return os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
