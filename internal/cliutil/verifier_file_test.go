// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"
)

const verifierSizeError = "input exceeds 8388608 bytes"

func TestReadVerifierFileSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	file, err := os.OpenFile(filepath.Clean(path), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := file.Truncate(MaxVerifierInputBytes + 1); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVerifierFile(path); err == nil || err.Error() != verifierSizeError {
		t.Fatalf("oversized file error = %v, want %q", err, verifierSizeError)
	}
	if err := file.Truncate(MaxVerifierInputBytes); err != nil {
		t.Fatal(err)
	}
	got, err := ReadVerifierFile(path)
	if err != nil || int64(len(got)) != MaxVerifierInputBytes {
		t.Fatalf("file at limit returned %d bytes, %v", len(got), err)
	}
}

func TestReadVerifierFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	if _, err := ReadVerifierFile(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error = %v, want %v", err, os.ErrNotExist)
	}
}

func TestReadBoundedVerifierInputErrors(t *testing.T) {
	if _, err := readBoundedVerifierInput(iotest.ErrReader(os.ErrPermission)); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("read error = %v, want %v", err, os.ErrPermission)
	}
	input := bytes.NewReader(make([]byte, MaxVerifierInputBytes+1))
	if _, err := readBoundedVerifierInput(input); err == nil || err.Error() != verifierSizeError {
		t.Fatalf("oversized read error = %v, want %q", err, verifierSizeError)
	}
}
