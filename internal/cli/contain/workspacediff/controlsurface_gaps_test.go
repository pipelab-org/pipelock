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

func TestControlSurfaceReportsPermissionOnlyChange(t *testing.T) {
	// Git runs a hook only when it is executable, so a mode flip activates
	// code without touching its content or digest.
	root := t.TempDir()
	writeControlFixture(t, root, ".git/hooks/pre-commit", "#!/bin/sh\nexit 0\n")
	before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	if err := os.Chmod(filepath.Join(root, ".git", "hooks", "pre-commit"), 0o700); err != nil { // #nosec G302 -- the executable bit is the behavior under test.
		t.Fatal(err)
	}
	after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	expectControlPath(t, controlDiff(t, before, after), ".git/hooks/pre-commit")
}

func TestControlSurfaceMissingWorkspaceRootIsIncomplete(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "workspace")
	writeControlFixture(t, root, ".envrc", "fixture")
	present := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	missing, err := SnapshotControlSurface(filepath.Join(dir, "absent"), testControlCap, DefaultControlSurfaceBudget())
	if err != nil {
		t.Fatal(err)
	}
	absentRoot := ControlSurfaceSnapshot{root: present.root, capBytes: present.capBytes, problem: missing.problem}
	if absentRoot.problem == "" {
		t.Fatal("a missing workspace root must be reported as a snapshot problem")
	}
	for name, pair := range map[string][2]ControlSurfaceSnapshot{
		"missing at start": {absentRoot, present},
		"missing at end":   {present, absentRoot},
	} {
		t.Run(name, func(t *testing.T) {
			diff := controlDiff(t, pair[0], pair[1])
			if !diff.Incomplete || !strings.Contains(diff.IncompleteReason, "stat workspace root") || diff.Changed {
				t.Fatalf("want an incomplete observation without a clean claim: %+v", diff)
			}
		})
	}
}

func TestControlSurfaceNonRegularControlPathIsIncomplete(t *testing.T) {
	root := t.TempDir()
	if err := makeFIFO(filepath.Join(root, ".envrc")); err != nil {
		t.Skipf("FIFOs are unavailable: %v", err)
	}
	snap := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	diff := controlDiff(t, snap, snap)
	if !diff.Incomplete || len(diff.Unreadable) != 1 || !strings.Contains(diff.Unreadable[0].Reason, "unsupported control path type") {
		t.Fatalf("a FIFO at a control path must fail closed: %+v", diff)
	}
}

func TestControlSurfaceDepthLimitIsIncomplete(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, ".claude/one/two/three/file", "fixture")
	budget := DefaultControlSurfaceBudget()
	budget.MaxControlDepth = 2
	snap := controlSnapshot(t, root, budget)
	diff := controlDiff(t, snap, snap)
	if !diff.Incomplete || !strings.Contains(diff.IncompleteReason, "control depth limit") {
		t.Fatalf("a path deeper than the depth budget must be incomplete: %+v", diff)
	}
}

func TestControlSurfaceEnumeratesHooksBeforeTheGitDirectoryRoot(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, ".git/config", "[core]\n\tfilemode = true\n")
	writeControlFixture(t, root, ".git/hooks/pre-commit", "before")
	for i := range 40 {
		writeControlFixture(t, root, filepath.Join(".git", "aaa-unrelated-"+string(rune('a'+i%26))+string(rune('a'+i/26))), "filler")
	}
	budget := DefaultControlSurfaceBudget()
	budget.MaxControlEntries = 12
	before := controlSnapshot(t, root, budget)
	writeControlFixture(t, root, ".git/hooks/pre-commit", "after, now longer")
	after := controlSnapshot(t, root, budget)
	diff := controlDiff(t, before, after)
	if !diff.Incomplete || !slices.Contains(diff.Modified, filepath.FromSlash(".git/hooks/pre-commit")) {
		t.Fatalf("a truncated pass must still observe hooks first: %+v", diff)
	}
}

func TestControlSurfaceObservesRedirectedCommonDirectory(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, "shared-git/config", "[core]\n\tfilemode = true\n")
	writeControlFixture(t, root, "shared-git/hooks/pre-commit", "before")
	writeControlFixture(t, root, ".git/HEAD", "ref: refs/heads/main\n")
	writeControlFixture(t, root, ".git/commondir", "../shared-git\n")
	before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	writeControlFixture(t, root, "shared-git/hooks/pre-commit", "after, now longer")
	after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	expectControlPath(t, controlDiff(t, before, after), "shared-git/hooks/pre-commit")
}

func TestControlSurfaceDoesNotInferAdditionsOrRemovalsFromATruncatedPass(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, ".git/config", "[core]\n\tfilemode = true\n")
	for i := range 10 {
		writeControlFixture(t, root, filepath.Join(".git", "hooks", "hook-"+string(rune('a'+i))), "fixture")
	}
	full := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	small := DefaultControlSurfaceBudget()
	small.MaxControlEntries = 5
	truncated := controlSnapshot(t, root, small)
	for name, pair := range map[string][2]ControlSurfaceSnapshot{
		"truncated at end":   {full, truncated},
		"truncated at start": {truncated, full},
	} {
		t.Run(name, func(t *testing.T) {
			diff := controlDiff(t, pair[0], pair[1])
			if !diff.Incomplete || len(diff.Added) != 0 || len(diff.Removed) != 0 || diff.Changed {
				t.Fatalf("a truncated pass cannot prove an addition or removal: %+v", diff)
			}
		})
	}
}
