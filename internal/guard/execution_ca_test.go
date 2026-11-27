// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package guard

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// CA bundle locations are optional candidates. Only entries whose target is a
// regular file are declared; anything else at a candidate path is skipped
// instead of being declared as a file that every layer would then reject.
func TestExecutionCAFilesKeepsOnlyRegularFileTargets(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "bundle.pem")
	if err := os.WriteFile(regular, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "bundle-dir.pem")
	if err := os.Mkdir(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing.pem")

	paths := []string{regular, directory, missing}
	want := []string{regular}
	if runtime.GOOS != "windows" {
		fileLink := filepath.Join(root, "file-link.pem")
		if err := os.Symlink("bundle.pem", fileLink); err != nil {
			t.Fatal(err)
		}
		dirLink := filepath.Join(root, "dir-link.pem")
		if err := os.Symlink("bundle-dir.pem", dirLink); err != nil {
			t.Fatal(err)
		}
		dangling := filepath.Join(root, "dangling.pem")
		if err := os.Symlink("missing.pem", dangling); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, fileLink, dirLink, dangling)
		want = append(want, fileLink)
	}

	original := executionCAPaths
	executionCAPaths = paths
	t.Cleanup(func() { executionCAPaths = original })

	if got := ExecutionCAFiles(); !slices.Equal(got, want) {
		t.Fatalf("ExecutionCAFiles() = %v, want %v", got, want)
	}
}
