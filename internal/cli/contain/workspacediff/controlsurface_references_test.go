// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func symlinkFixture(t *testing.T, root, target, name string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

// A Git configuration that is a symlink has its target recorded because the link
// names it. A snapshot that never examined the repository holding the link does
// not know whether the target exists, so it cannot show it removed.
func TestControlSurfaceInfersNothingFromASymlinkedConfigOfAnUnexaminedRepository(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	git.init(t, root)
	nested := filepath.Join(root, "x", "y", "a")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	git.init(t, nested)
	const target = "shared.cfg"
	writeControlFixture(t, root, target, "[example]\n\tkey = value\n")
	config := filepath.Join(nested, ".git", "config")
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	// The link sits four directories below the workspace root.
	if err := os.Symlink("../../../../"+target, config); err != nil {
		t.Fatal(err)
	}
	full := DefaultControlSurfaceBudget()
	shallow := full
	shallow.MaxNestedDepth = 2
	complete := controlSnapshot(t, root, full)
	if _, observed := complete.nested.entries[target]; !observed {
		t.Fatal("test setup: discovery must follow the nested repository's config link")
	}
	cutOff := controlSnapshot(t, root, shallow)
	for name, pair := range map[string][2]ControlSurfaceSnapshot{
		"unexamined at end":   {complete, cutOff},
		"unexamined at start": {cutOff, complete},
	} {
		t.Run(name, func(t *testing.T) {
			diff := controlDiff(t, pair[0], pair[1])
			if !diff.NestedDiscoveryPartial || diff.Incomplete || diff.Changed {
				t.Fatalf("a repository that was not examined proves no change to what its config link names: %+v", diff)
			}
		})
	}
}

// A repository whose configuration cannot be read in one snapshot, here for being
// over the digest cap, does not show the files it includes. A snapshot that read
// it must not report those files added or removed on that account; a path both
// snapshots observed independently is still compared.
func TestControlSurfaceInfersNothingFromAnUnreadableConfigsReferences(t *testing.T) {
	for _, tc := range []struct {
		name string
		// target is the included path; a fixed control path is one discovery
		// reaches on its own.
		target string
		change func(t *testing.T, root string)
		// wantChange says whether the change to the target must still be reported.
		wantChange bool
	}{
		{"only the config names the target", "shared.cfg", func(t *testing.T, root string) {}, false},
		{"the target is also a fixed control path", ".mcp.json", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, ".mcp.json")); err != nil {
				t.Fatal(err)
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			includeTarget := "[include]\n\tpath = ../" + tc.target + "\n"
			writeControlFixture(t, root, ".git/HEAD", "ref: refs/heads/main\n")
			writeControlFixture(t, root, ".git/config", includeTarget)
			writeControlFixture(t, root, tc.target, "[example]\n\tkey = value\n")
			readable := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			if _, observed := readable.priority.entries[tc.target]; !observed {
				t.Fatal("test setup: the include must be followed while the config is readable")
			}
			tc.change(t, root)
			// The same include stays in the file, but the file is now over the cap.
			writeControlFixture(t, root, ".git/config", includeTarget+"# "+strings.Repeat("x", testControlCap)+"\n")
			oversize := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			if _, observed := oversize.priority.entries[tc.target]; observed && !tc.wantChange {
				t.Fatal("test setup: an oversize config must not be followed")
			}
			for name, pair := range map[string][2]ControlSurfaceSnapshot{
				"unreadable at end":   {readable, oversize},
				"unreadable at start": {oversize, readable},
			} {
				t.Run(name, func(t *testing.T) {
					diff := controlDiff(t, pair[0], pair[1])
					if !diff.Incomplete {
						t.Fatalf("an oversize config must make the observation incomplete: %+v", diff)
					}
					reported := slices.Contains(diff.Paths(), filepath.FromSlash(tc.target))
					if reported != tc.wantChange {
						t.Fatalf("%s reported = %t, want %t: %+v", tc.target, reported, tc.wantChange, diff)
					}
				})
			}
		})
	}
}

// Git resolves a gitfile that names a symlink to the directory behind it, so the
// directory is the repository's Git directory: its configuration's hook paths and
// includes are followed, and its volatile files stay out of the report.
func TestControlSurfaceFollowsASymlinkedGitDirectoryPointer(t *testing.T) {
	prepare := func(t *testing.T, root string, link func()) {
		t.Helper()
		writeControlFixture(t, root, ".git", "gitdir: meta\n")
		writeControlFixture(t, root, "real/HEAD", "ref: refs/heads/main\n")
		writeControlFixture(t, root, "real/config", "[core]\n\thooksPath = ../hk\n")
		writeControlFixture(t, root, "hk/pre-commit", "before")
		link()
	}
	for _, tc := range []struct {
		name string
		link func(t *testing.T, root string)
	}{
		{"one link", func(t *testing.T, root string) { symlinkFixture(t, root, "real", "meta") }},
		{"link chain", func(t *testing.T, root string) {
			symlinkFixture(t, root, "real", "hop")
			symlinkFixture(t, root, "hop", "meta")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			prepare(t, root, func() { tc.link(t, root) })
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			writeControlFixture(t, root, "hk/pre-commit", "changed")
			expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, budget)), "hk/pre-commit")
		})
	}
	t.Run("volatile files stay volatile behind the link", func(t *testing.T) {
		root := t.TempDir()
		prepare(t, root, func() { symlinkFixture(t, root, "real", "meta") })
		budget := DefaultControlSurfaceBudget()
		before := controlSnapshot(t, root, budget)
		writeControlFixture(t, root, "real/HEAD", "ref: refs/heads/other\n")
		writeControlFixture(t, root, "real/index", "index")
		if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); diff.Changed || diff.Incomplete {
			t.Fatalf("Git's own bookkeeping behind a symlinked Git directory must stay volatile: %+v", diff)
		}
	})
	t.Run("a target outside the workspace cannot be observed", func(t *testing.T) {
		root := t.TempDir()
		writeControlFixture(t, root, ".git", "gitdir: meta\n")
		symlinkFixture(t, root, t.TempDir(), "meta")
		budget := DefaultControlSurfaceBudget()
		diff := controlDiff(t, controlSnapshot(t, root, budget), controlSnapshot(t, root, budget))
		var named bool
		for _, entry := range diff.Unreadable {
			named = named || entry.Path == ".git"
		}
		if !diff.Incomplete || !named {
			t.Fatalf("an unresolvable Git directory pointer must be reported unreadable: %+v", diff)
		}
	})
}
