// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package workspacediff

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const bindMountChildEnv = "WORKSPACEDIFF_BIND_MOUNT_CHILD"

// A path swapped to a bind mount of the same file keeps its device and inode, so
// the identity check passes, and a pathname lookup made after the open reports
// the new mount for both sides. Only the workspace mount the walk checked
// exposes it. The swap needs a mount namespace of its own, so the test runs
// itself under unshare and skips where that is not permitted.
func TestSnapshotRefusesSameInodeBindMountSwap(t *testing.T) {
	if os.Getenv(bindMountChildEnv) == "" {
		unshare, err := exec.LookPath("unshare")
		if err != nil {
			t.Skip("unshare is required for a private mount namespace")
		}
		cmd := exec.CommandContext(t.Context(), unshare, "-Urm", os.Args[0], "-test.run=^TestSnapshotRefusesSameInodeBindMountSwap$", "-test.v") // #nosec G204 -- the test re-runs its own binary.
		cmd.Env = append(os.Environ(), bindMountChildEnv+"=1")
		output, err := cmd.CombinedOutput()
		switch {
		case strings.Contains(string(output), "--- SKIP"), strings.Contains(string(output), "unshare failed"):
			t.Skipf("a private mount namespace is unavailable:\n%s", output)
		case err != nil:
			t.Fatalf("child run failed: %v\n%s", err, output)
		}
		return
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	writeFile(t, path, "content")
	workspaceMount, ok := mountID(dir)
	if !ok {
		t.Skip("mount IDs are unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino, ok := statIDs(info)
	if !ok {
		t.Skip("statIDs unavailable on this platform")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := unix.Mount(path, path, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("bind mount is not permitted here: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(path, 0) })
	if swapped, _ := mountID(path); swapped == workspaceMount {
		t.Fatal("test setup: the bind mount did not create a new mount")
	}
	file := snapshotFile{
		root: root, relPath: "file", path: path, dev: dev, ino: ino, haveIDs: true,
		workspaceMount: workspaceMount, workspaceMountKnown: true,
	}
	if _, _, err := hashFileSafe(file, 1<<20); err == nil || !strings.Contains(err.Error(), "mount changed") {
		t.Fatalf("a file swapped to a bind mount of the same inode must be refused, got %v", err)
	}
	file.workspaceMountKnown = false
	if _, _, err := hashFileSafe(file, 1<<20); err != nil {
		t.Fatalf("without mount IDs the walk's device check is the boundary: %v", err)
	}
}
