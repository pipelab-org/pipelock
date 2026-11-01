// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package testexec_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testexec"
)

func TestWriteReplacesContentAndMode(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("old content that is longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := testexec.Write(path, []byte("new"), 0o700); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test-owned path.
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("new")) {
		t.Fatalf("content = %q, want %q", got, "new")
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Fatalf("mode = %v, want 0700", mode)
	}
}

func TestWriteReportsOpenFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing", "fixture")
	if err := testexec.Write(path, []byte("x"), 0o700); err == nil {
		t.Fatal("Write into a missing directory succeeded")
	}
}
