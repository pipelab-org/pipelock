// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"os"
	"path/filepath"
	"testing"
)

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
