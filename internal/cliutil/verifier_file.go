// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Verifier inputs are commonly supplied by a different trust domain. Keep the
// ceiling aligned with the maximum evidence shard accepted by the receipt
// verifier so a malformed standalone artifact cannot allocate without bound.
const MaxVerifierInputBytes int64 = 8 << 20

// ReadVerifierFile reads one bounded, regular verification artifact.
func ReadVerifierFile(path string) ([]byte, error) {
	clean, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return nil, err
	}
	file, err := root.Open(filepath.Base(clean))
	closeErr := root.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, closeErr
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat input: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("input must be a regular file")
	}
	if info.Size() > MaxVerifierInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", MaxVerifierInputBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, MaxVerifierInputBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxVerifierInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", MaxVerifierInputBytes)
	}
	return data, nil
}
