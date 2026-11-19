// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Verifier inputs are commonly supplied by a different trust domain. Keep the
// ceiling aligned with the maximum evidence shard accepted by the receipt
// verifier so a malformed standalone artifact cannot allocate without bound.
const MaxVerifierInputBytes int64 = 8 << 20

var errVerifierFileType = errors.New("input must be a regular file")

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
	file, err := openVerifierFile(root, filepath.Base(clean))
	_ = root.Close()
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	return readBoundedVerifierInput(file)
}

func readBoundedVerifierInput(input io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, MaxVerifierInputBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxVerifierInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", MaxVerifierInputBytes)
	}
	return data, nil
}

// openCheckedVerifierFile verifies the opened file, including replacements that
// occurred after checking the path.
func openCheckedVerifierFile(root *os.Root, name string, flags int) (*os.File, error) {
	file, err := root.OpenFile(name, flags, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat input: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errVerifierFileType
	}
	if info.Size() > MaxVerifierInputBytes {
		_ = file.Close()
		return nil, fmt.Errorf("input exceeds %d bytes", MaxVerifierInputBytes)
	}
	return file, nil
}
