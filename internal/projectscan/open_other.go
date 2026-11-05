// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package projectscan

import (
	"os"
	"path/filepath"
)

// openNoBlock opens path read-only. Platforms without Unix FIFOs at regular
// paths, such as Windows and WebAssembly, have no blocking open to avoid.
func openNoBlock(path string) (*os.File, error) {
	return os.Open(filepath.Clean(path))
}
