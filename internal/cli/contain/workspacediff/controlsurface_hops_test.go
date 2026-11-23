// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// linkChain makes total symlinks, the first at first and the rest at the root of
// the workspace, each naming the next and the last naming final. Both are
// relative to the root.
func linkChain(t *testing.T, root, first, final string, total int) {
	t.Helper()
	name := func(i int) string {
		if i == 0 {
			return first
		}
		return fmt.Sprintf("chain%d", i)
	}
	for i := range total {
		target := final
		if i < total-1 {
			target = name(i + 1)
		}
		rel, err := filepath.Rel(filepath.Dir(name(i)), target)
		if err != nil {
			t.Fatal(err)
		}
		symlinkFixture(t, root, rel, name(i))
	}
}

// expectKernelHops checks the fixture against the kernel, which resolves 40
// symlinks in one lookup and refuses the 41st.
func expectKernelHops(t *testing.T, path string, resolves bool) {
	t.Helper()
	_, err := os.Stat(path)
	if resolves != (err == nil) || (!resolves && !errors.Is(err, syscall.ELOOP)) {
		t.Fatalf("the kernel resolving %s: err = %v, want resolves = %t", path, err, resolves)
	}
}

// Every loop that follows symlinks stops at the same place as the kernel: a
// chain of 40 links reaches what it names, and the 41st link is refused. The
// limit is checked before another link is followed, never before the current
// entry is looked at, so the target of the 40th link is read.
func TestControlSurfaceLinkLimitMatchesTheKernel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		links int
		ok    bool
	}{
		{"the most links the kernel allows", maxConfigLinkHops, true},
		{"one link too many", maxConfigLinkHops + 1, false},
	} {
		t.Run("config chain, "+tc.name, func(t *testing.T) {
			git := newControlGit(t)
			root := t.TempDir()
			git.init(t, root)
			writeControlFixture(t, root, "real.cfg", "[core]\n\thooksPath = selected-hooks\n")
			writeControlFixture(t, root, "selected-hooks/pre-commit", "before")
			if err := os.Remove(filepath.Join(root, ".git", "config")); err != nil {
				t.Fatal(err)
			}
			linkChain(t, root, ".git/config", "real.cfg", tc.links)
			expectKernelHops(t, filepath.Join(root, ".git", "config"), tc.ok)
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			if !tc.ok {
				expectUnreadable(t, controlDiff(t, before, controlSnapshot(t, root, budget)), ".git/config", "chain is too long")
				return
			}
			writeControlFixture(t, root, "selected-hooks/pre-commit", "changed")
			expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, budget)), "selected-hooks/pre-commit")
		})
		t.Run("Git directory pointer chain, "+tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeControlFixture(t, root, ".git", "gitdir: pointer\n")
			writeControlFixture(t, root, "realgit/hooks/pre-commit", "before")
			linkChain(t, root, "pointer", "realgit", tc.links)
			expectKernelHops(t, filepath.Join(root, "pointer"), tc.ok)
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			if !tc.ok {
				expectUnreadable(t, controlDiff(t, before, controlSnapshot(t, root, budget)), ".git", "Git directory symlink target could not be observed")
				return
			}
			writeControlFixture(t, root, "realgit/hooks/pre-commit", "changed")
			expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, budget)), "realgit/hooks/pre-commit")
		})
		t.Run("symlinked directory chain, "+tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeControlFixture(t, root, "real/x", "x")
			linkChain(t, root, "chain0", "real", tc.links)
			expectKernelHops(t, filepath.Join(root, "chain0", "x"), tc.ok)
			w := newTestWalker(t, root)
			got, res := w.resolveWorkspacePath("source", ".", "chain0/x")
			if tc.ok && (res != pathResolved || got != "real/x") {
				t.Fatalf("resolve = %q, %v, want real/x resolved", got, res)
			}
			if !tc.ok && (res != pathUnobservable || w.pass.unreadable["source"] != "configured path symlink chain is too long") {
				t.Fatalf("resolve = %q, %v, unreadable = %v", got, res, w.pass.unreadable)
			}
		})
	}
}
