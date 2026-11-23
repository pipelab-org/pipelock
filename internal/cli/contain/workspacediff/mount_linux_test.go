// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package workspacediff

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	bindMountChildEnv = "WORKSPACEDIFF_BIND_MOUNT_CHILD"
	// bindMountChildReady is printed once the child runs inside the namespace.
	// A failure without it happened while unshare set the namespace up, whatever
	// language its message is in.
	bindMountChildReady = "WORKSPACEDIFF_BIND_MOUNT_CHILD_READY"
)

// bindMountChildResult classifies the output of the test re-run under unshare.
// A run that never reached the test body could not create the namespace, so it
// is skipped; any failure after that is a genuine one.
func bindMountChildResult(output string, runErr error) (skip bool, err error) {
	reached := strings.Contains(output, bindMountChildReady)
	switch {
	case runErr != nil && !reached:
		return true, nil
	case runErr != nil:
		return false, fmt.Errorf("child run failed: %w", runErr)
	case strings.Contains(output, "--- SKIP"):
		return true, nil
	}
	return false, nil
}

func TestBindMountChildResult(t *testing.T) {
	failure := errors.New("exit status 1")
	for _, tc := range []struct {
		name     string
		output   string
		err      error
		wantSkip bool
		wantErr  bool
	}{
		{"unshare refused in English", "unshare failed: Operation not permitted\n", failure, true, false},
		{"unshare refused in another language", "unshare: schreiben von /proc/self/uid_map fehlgeschlagen\n", failure, true, false},
		{"namespace setup failed with no output", "", failure, true, false},
		{"assertion failed inside the namespace", bindMountChildReady + "\n--- FAIL: TestSnapshotRefusesSameInodeBindMountSwap\n", failure, false, true},
		{"child skipped inside the namespace", bindMountChildReady + "\n--- SKIP: bind mount is not permitted here\n", nil, true, false},
		{"child passed", bindMountChildReady + "\n--- PASS: TestSnapshotRefusesSameInodeBindMountSwap\n", nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			skip, err := bindMountChildResult(tc.output, tc.err)
			if skip != tc.wantSkip || (err != nil) != tc.wantErr {
				t.Fatalf("bindMountChildResult = skip:%t err:%v, want skip:%t err:%t", skip, err, tc.wantSkip, tc.wantErr)
			}
		})
	}
}

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
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), unshare, "-Urm", self, "-test.run=^TestSnapshotRefusesSameInodeBindMountSwap$", "-test.v") // #nosec G204 -- the test re-runs its own binary under unshare.
		cmd.Env = append(os.Environ(), "LC_ALL=C", bindMountChildEnv+"=1")
		output, runErr := cmd.CombinedOutput()
		skip, err := bindMountChildResult(string(output), runErr)
		if skip {
			t.Skipf("a private mount namespace is unavailable:\n%s", output)
		}
		if err != nil {
			t.Fatalf("%v\n%s", err, output)
		}
		return
	}
	_, _ = fmt.Fprintln(os.Stdout, bindMountChildReady)

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
