// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package workspacediff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlWalkerRefusesAMountOrDeviceBoundary(t *testing.T) {
	t.Run("a file read from another mount", func(t *testing.T) {
		root := t.TempDir()
		writeControlFixture(t, root, ".git/config", "[core]\n")
		w := newTestWalker(t, root)
		if !w.mountKnown {
			t.Skip("mount IDs are unavailable")
		}
		entry := observeFile(t, w, ".git/config")
		w.rootMount++
		if data, ok := w.readObserved(entry); ok || data != nil {
			t.Fatalf("a file on another mount must not be read: %q", data)
		}
		if reason := w.pass.unreadable[".git/config"]; !strings.Contains(reason, "mount changed between walk and open") {
			t.Fatalf("unreadable reason = %q", reason)
		}
		if w.lookup(".git/config") != nil {
			t.Fatal("a lookup that crosses a mount must observe nothing")
		}
	})
	t.Run("another mount", func(t *testing.T) {
		root := t.TempDir()
		w := newTestWalker(t, root)
		if !w.mountKnown {
			t.Skip("mount IDs are unavailable")
		}
		if w.checkMount("inside", w.rootInfo, w.rootMount+1, true) {
			t.Fatal("a path on another mount must be refused")
		}
		if reason := w.pass.unreadable["inside"]; reason != "crossed a mount boundary" {
			t.Fatalf("unreadable reason = %q", reason)
		}
	})
	t.Run("another device without mount IDs", func(t *testing.T) {
		root := t.TempDir()
		w := newTestWalker(t, root)
		w.mountKnown = false
		other, err := os.Lstat("/proc")
		if err != nil {
			t.Skipf("no second device to compare: %v", err)
		}
		rootDev, _, ok := statIDsWithInode(w.rootInfo)
		procDev, _, procOK := statIDsWithInode(other)
		if !ok || !procOK || rootDev == procDev {
			t.Skip("/proc shares the workspace device")
		}
		if w.checkMount("proc", other, 0, false) {
			t.Fatal("a path on another device must be refused when mount IDs are unavailable")
		}
		if reason := w.pass.unreadable["proc"]; reason != "crossed a device boundary" || !w.deviceOnly {
			t.Fatalf("unreadable reason = %q, deviceOnly = %t", reason, w.deviceOnly)
		}
		// The same device passes, but the observation is marked device-only.
		if !w.checkMount("same", w.rootInfo, 0, false) {
			t.Fatal("a path on the workspace device passes the device check")
		}
	})
}

// denyAccess removes every permission from path and restores it afterwards. It
// skips the test where the permission is not enforced, such as for root.
func denyAccess(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode().Perm()
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, mode) })
	if f, err := os.Open(filepath.Clean(path)); err == nil {
		_ = f.Close()
		t.Skip("file permissions are not enforced for this user")
	}
}

func TestControlSurfaceReportsPathsItCannotOpen(t *testing.T) {
	t.Run("a control file that cannot be hashed", func(t *testing.T) {
		root := t.TempDir()
		writeControlFixture(t, root, ".envrc", "fixture")
		denyAccess(t, filepath.Join(root, ".envrc"))
		w := newTestWalker(t, root)
		if entry := w.recordPath(".envrc"); entry.Kind != "" {
			t.Fatalf("an unreadable file must not be recorded as observed: %+v", entry)
		}
		if reason := w.pass.unreadable[".envrc"]; !strings.Contains(reason, "hash file") {
			t.Fatalf("unreadable reason = %q", reason)
		}
	})
	t.Run("a control directory that cannot be opened", func(t *testing.T) {
		root := t.TempDir()
		writeControlFixture(t, root, ".claude/settings.json", "{}")
		denyAccess(t, filepath.Join(root, ".claude"))
		snap := controlSnapshot(t, root, DefaultControlSurfaceBudget())
		diff := controlDiff(t, snap, snap)
		if !diff.Incomplete || diff.Changed {
			t.Fatalf("a directory that cannot be listed must be incomplete without a clean claim: %+v", diff)
		}
		var named bool
		for _, entry := range diff.Unreadable {
			named = named || (entry.Path == ".claude" && strings.Contains(entry.Reason, "open directory"))
		}
		if !named {
			t.Fatalf("the directory must be named unreadable: %+v", diff.Unreadable)
		}
	})
}

func TestControlSurfaceReportsAWorkspaceRootItCannotOpen(t *testing.T) {
	root := t.TempDir()
	denyAccess(t, root)
	snap, err := SnapshotControlSurface(root, testControlCap, DefaultControlSurfaceBudget())
	if err != nil || !strings.Contains(snap.problem, "open workspace root") {
		t.Fatalf("snapshot problem = %q, err = %v", snap.problem, err)
	}
	diff := controlDiff(t, snap, snap)
	if !diff.Incomplete || diff.Changed || !strings.Contains(diff.IncompleteReason, "open workspace root") {
		t.Fatalf("a root that cannot be opened must be incomplete without a clean claim: %+v", diff)
	}
}
