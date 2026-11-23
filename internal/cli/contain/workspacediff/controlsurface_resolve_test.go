// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeControlHook writes an executable hook that prints marker when Git runs it.
func writeControlHook(t *testing.T, root, path, marker string) {
	t.Helper()
	writeControlFixture(t, root, path, "#!/bin/sh\necho "+marker+"\n")
	// #nosec G302 -- Git runs the fixture hook, which has to be executable.
	if err := os.Chmod(filepath.Join(root, filepath.FromSlash(path)), 0o700); err != nil {
		t.Fatal(err)
	}
}

// Git resolves a path its configuration names through the filesystem, following
// a symlinked directory wherever it appears in the path. Each case confirms the
// answer with Git itself, then expects the observation to watch the same place.
func TestControlSurfaceFollowsConfiguredPathsThroughSymlinkedDirectories(t *testing.T) {
	const editedContent = "[example]\n\tkey = changed\n"
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, git testGit, root string)
		// gitConfig and gitHook are what Git itself reports for the fixture.
		gitConfig, gitHook string
		// edits must be reported; decoys, which Git does not use, must not be.
		edits, decoys []string
	}{
		{
			name: "include through a symlinked directory names a hooks path",
			prepare: func(t *testing.T, git testGit, root string) {
				symlinkFixture(t, root, "configs", "alias")
				writeControlFixture(t, root, "configs/extra.cfg", "[core]\n\thooksPath = selected-hooks\n")
				writeControlHook(t, root, "selected-hooks/pre-commit", "selected")
				git.run(t, root, "config", "--local", "include.path", "../alias/extra.cfg")
			},
			gitConfig: "selected-hooks", gitHook: "selected",
			edits: []string{"selected-hooks/pre-commit", "configs/extra.cfg"},
		},
		{
			name: "conditional include through a symlinked directory",
			prepare: func(t *testing.T, git testGit, root string) {
				symlinkFixture(t, root, "configs", "alias")
				writeControlFixture(t, root, "configs/extra.cfg", "[core]\n\thooksPath = selected-hooks\n")
				writeControlHook(t, root, "selected-hooks/pre-commit", "selected")
				git.run(t, root, "config", "--local", "includeIf.gitdir:"+root+"/.path", "../alias/extra.cfg")
			},
			gitConfig: "selected-hooks", gitHook: "selected",
			edits: []string{"selected-hooks/pre-commit"},
		},
		{
			name: "hooks path through a symlinked directory",
			prepare: func(t *testing.T, git testGit, root string) {
				symlinkFixture(t, root, "real", "alias")
				writeControlHook(t, root, "real/hooks/pre-commit", "through-alias")
				git.run(t, root, "config", "--local", "core.hooksPath", "alias/hooks")
			},
			gitHook: "through-alias",
			edits:   []string{"real/hooks/pre-commit"},
		},
		{
			name: "dot-dot after a symlinked directory lands where Git does",
			prepare: func(t *testing.T, git testGit, root string) {
				symlinkFixture(t, root, "deep/sub", "jump")
				writeControlFixture(t, root, "deep/sub/keep", "keep")
				writeControlHook(t, root, "deep/hooks/pre-commit", "deep")
				writeControlHook(t, root, "hooks/pre-commit", "lexical")
				git.run(t, root, "config", "--local", "core.hooksPath", "jump/../hooks")
			},
			gitHook: "deep",
			edits:   []string{"deep/hooks/pre-commit"},
			decoys:  []string{"hooks/pre-commit"},
		},
		{
			name: "dot-dot out of a chain of symlinked directories",
			prepare: func(t *testing.T, git testGit, root string) {
				symlinkFixture(t, root, "two", "one")
				symlinkFixture(t, root, "base/inner", "two")
				writeControlFixture(t, root, "base/inner/keep", "keep")
				writeControlHook(t, root, "base/hooks/pre-commit", "base")
				writeControlHook(t, root, "hooks/pre-commit", "lexical")
				git.run(t, root, "config", "--local", "core.hooksPath", "one/../hooks")
			},
			gitHook: "base",
			edits:   []string{"base/hooks/pre-commit"},
			decoys:  []string{"hooks/pre-commit"},
		},
		{
			name: "absolute link into the workspace",
			prepare: func(t *testing.T, git testGit, root string) {
				symlinkFixture(t, root, filepath.Join(root, "real"), "alias")
				writeControlHook(t, root, "real/hooks/pre-commit", "absolute")
				git.run(t, root, "config", "--local", "core.hooksPath", "alias/hooks")
			},
			gitHook: "absolute",
			edits:   []string{"real/hooks/pre-commit"},
		},
		{
			name: "absolute link naming the workspace root",
			prepare: func(t *testing.T, git testGit, root string) {
				symlinkFixture(t, root, root, "home")
				writeControlHook(t, root, "real/hooks/pre-commit", "via-root")
				git.run(t, root, "config", "--local", "core.hooksPath", "home/real/hooks")
			},
			gitHook: "via-root",
			edits:   []string{"real/hooks/pre-commit"},
		},
		{
			name: "filesystem monitor through a symlinked directory",
			prepare: func(t *testing.T, git testGit, root string) {
				symlinkFixture(t, root, "real", "alias")
				writeControlFixture(t, root, "real/monitor", "before")
				git.run(t, root, "config", "--local", "core.fsmonitor", "alias/monitor")
			},
			edits: []string{"real/monitor"},
		},
		{
			name: "gitdir pointer through a symlinked directory",
			prepare: func(t *testing.T, _ testGit, root string) {
				symlinkFixture(t, root, "real", "alias")
				writeControlFixture(t, root, "proj/.git", "gitdir: ../alias/gitdata\n")
				writeControlFixture(t, root, "real/gitdata/hooks/pre-commit", "before")
			},
			edits: []string{"real/gitdata/hooks/pre-commit"},
		},
		{
			name: "common directory pointer through a symlinked directory",
			prepare: func(t *testing.T, _ testGit, root string) {
				symlinkFixture(t, root, "real", "alias")
				writeControlFixture(t, root, ".git/commondir", "../alias/common\n")
				writeControlFixture(t, root, "real/common/hooks/pre-commit", "before")
			},
			edits: []string{"real/common/hooks/pre-commit"},
		},
		{
			name: "worktree setting through a symlinked directory",
			prepare: func(t *testing.T, git testGit, root string) {
				symlinkFixture(t, root, "real", "alias")
				writeControlFixture(t, root, "real/wt/keep", "keep")
				writeControlFixture(t, root, "real/wt/hk/pre-commit", "before")
				git.run(t, root, "config", "--local", "core.hooksPath", "hk")
				git.run(t, root, "config", "--local", "core.worktree", "../alias/wt")
			},
			edits: []string{"real/wt/hk/pre-commit"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			git := newControlGit(t)
			root := t.TempDir()
			git.init(t, root)
			tc.prepare(t, git, root)
			if tc.gitConfig != "" {
				out, err := git.command(t, root, "config", "--includes", "--get", "core.hooksPath")
				if err != nil || strings.TrimSpace(out) != tc.gitConfig {
					t.Fatalf("Git reads core.hooksPath = %q (%v), want %q", out, err, tc.gitConfig)
				}
			}
			if tc.gitHook != "" {
				out, err := git.command(t, root, "hook", "run", "pre-commit")
				if err != nil || strings.TrimSpace(out) != tc.gitHook {
					t.Fatalf("Git runs the hook %q (%v), want %q", out, err, tc.gitHook)
				}
			}
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); diff.Changed || diff.Incomplete {
				t.Fatalf("an unchanged workspace must read clean and complete: %+v", diff)
			}
			for _, decoy := range tc.decoys {
				writeControlFixture(t, root, decoy, editedContent)
				if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); slices.Contains(diff.Paths(), filepath.FromSlash(decoy)) {
					t.Fatalf("%s is not where Git looks, and must not be reported: %+v", decoy, diff)
				}
			}
			for _, edit := range tc.edits {
				t.Run("edit "+edit, func(t *testing.T) {
					edited := controlSnapshot(t, root, budget)
					writeControlFixture(t, root, edit, "[example]\n\tkey = "+edit+"\n")
					expectControlPath(t, controlDiff(t, edited, controlSnapshot(t, root, budget)), edit)
				})
			}
		})
	}
}

// The kernel stops a path after 40 symlinks, and a loop never ends. Either way
// the file that named the path could not be followed, so it is named unreadable.
func TestControlSurfaceReportsASymlinkedDirectoryChainItCannotFollow(t *testing.T) {
	// chain makes d0 -> d1 -> ... -> real, count links long.
	chain := func(t *testing.T, root string, count int) {
		t.Helper()
		writeControlFixture(t, root, "real/extra.cfg", "[core]\n\thooksPath = selected-hooks\n")
		writeControlFixture(t, root, "selected-hooks/pre-commit", "before")
		for i := range count {
			target := fmt.Sprintf("d%d", i+1)
			if i == count-1 {
				target = "real"
			}
			symlinkFixture(t, root, target, fmt.Sprintf("d%d", i))
		}
	}
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, root string)
		include string
		follows bool
	}{
		{"the most links the kernel allows", func(t *testing.T, root string) { chain(t, root, maxConfigLinkHops) }, "../d0/extra.cfg", true},
		{"one link too many", func(t *testing.T, root string) { chain(t, root, maxConfigLinkHops+1) }, "../d0/extra.cfg", false},
		{"a loop", func(t *testing.T, root string) {
			symlinkFixture(t, root, "loop2", "loop")
			symlinkFixture(t, root, "loop", "loop2")
		}, "../loop/extra.cfg", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			git := newControlGit(t)
			root := t.TempDir()
			git.init(t, root)
			tc.prepare(t, root)
			git.run(t, root, "config", "--local", "include.path", tc.include)
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			if tc.follows {
				writeControlFixture(t, root, "selected-hooks/pre-commit", "changed")
				expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, budget)), "selected-hooks/pre-commit")
				return
			}
			expectUnreadable(t, controlDiff(t, before, controlSnapshot(t, root, budget)), ".git/config", "symlink chain is too long")
		})
	}
}

// A symlinked directory that leaves the grant is not followed, so what lies
// behind it is neither watched nor reported as added or removed.
func TestControlSurfaceDoesNotFollowASymlinkedDirectoryOutOfTheWorkspace(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target func(root, outside string) string
	}{
		{"absolute", func(_, outside string) string { return outside }},
		{"relative", func(root, outside string) string {
			rel, err := filepath.Rel(root, outside)
			if err != nil {
				t.Fatal(err)
			}
			return rel
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			git := newControlGit(t)
			root, outside := t.TempDir(), t.TempDir()
			git.init(t, root)
			writeControlFixture(t, outside, "extra.cfg", "[core]\n\thooksPath = selected-hooks\n")
			writeControlFixture(t, root, "selected-hooks/pre-commit", "before")
			symlinkFixture(t, root, tc.target(root, outside), "alias")
			git.run(t, root, "config", "--local", "include.path", "../alias/extra.cfg")
			git.run(t, root, "config", "--local", "core.fsmonitor", "alias/monitor")
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			writeControlFixture(t, outside, "extra.cfg", "[core]\n\thooksPath = elsewhere\n")
			writeControlFixture(t, outside, "monitor", "created behind the link")
			if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); diff.Changed || diff.Incomplete {
				t.Fatalf("a place outside the grant is out of scope: %+v", diff)
			}
		})
	}
}

// A path that names nothing yet is no configuration, not an observation
// problem; creating what it names is an addition.
func TestControlSurfaceTreatsAnAbsentIncludeThroughSymlinksAsNoConfiguration(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	git.init(t, root)
	writeControlFixture(t, root, "configs/keep", "keep")
	symlinkFixture(t, root, "configs", "alias")
	git.run(t, root, "config", "--local", "include.path", "../nodir/extra.cfg")
	git.run(t, root, "config", "--local", "--add", "include.path", "../alias/missing.cfg")
	git.run(t, root, "config", "--local", "--add", "include.path", "../alias/keep/inner.cfg")
	budget := DefaultControlSurfaceBudget()
	before := controlSnapshot(t, root, budget)
	if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); diff.Changed || diff.Incomplete {
		t.Fatalf("an include that names nothing must read clean and complete: %+v", diff)
	}
	for _, created := range []string{"nodir/extra.cfg", "configs/missing.cfg"} {
		writeControlFixture(t, root, created, "[example]\n\tkey = value\n")
		expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, budget)), created)
	}
}

// A link naming a path through a directory that does not exist is dangling, as
// the kernel finds it, not ambiguous. Once the directory exists the path resolves
// and what it names is observed.
func TestControlSurfaceResolvesADanglingLinkWithAnAbsoluteDotDot(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, "b/target", "fixture")
	symlinkFixture(t, root, root+"/a/../b", ".claude/link")
	budget := DefaultControlSurfaceBudget()
	before := controlSnapshot(t, root, budget)
	if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); diff.Changed || diff.Incomplete {
		t.Fatalf("a dangling link names nothing to observe: %+v", diff)
	}
	writeControlFixture(t, root, "a/keep", "keep")
	diff := controlDiff(t, before, controlSnapshot(t, root, budget))
	if diff.Incomplete || !slices.Contains(diff.Added, filepath.FromSlash("b/target")) {
		t.Fatalf("a link that now resolves must have its target observed: %+v", diff)
	}
}

func TestControlWalkerResolvesWorkspacePaths(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeControlFixture(t, root, "plain/keep", "x")
	writeControlFixture(t, root, "file", "x")
	writeControlFixture(t, root, "deep/sub/keep", "x")
	symlinkFixture(t, root, "plain", "alias")
	symlinkFixture(t, root, filepath.Join(root, "plain"), "abs")
	symlinkFixture(t, root, root, "toroot")
	symlinkFixture(t, root, "deep/sub", "jump")
	symlinkFixture(t, root, "../"+filepath.Base(outside), "leaves")
	symlinkFixture(t, root, outside, "absout")
	for _, tc := range []struct {
		name, base, value string
		want              string
		res               pathResolution
		unreadable        string
	}{
		{"plain directories", ".", "plain/x", "plain/x", pathResolved, ""},
		{"a symlinked directory", ".", "alias/x", "plain/x", pathResolved, ""},
		{"a final symlink is left for the caller", ".", "alias", "alias", pathResolved, ""},
		{"an absolute link into the workspace", ".", "abs/x", "plain/x", pathResolved, ""},
		{"an absolute link naming the root", ".", "toroot/plain/x", "plain/x", pathResolved, ""},
		{"an absolute value naming the root", ".", root, ".", pathResolved, ""},
		{"an absolute value under the root", ".", root + "/alias/x", "plain/x", pathResolved, ""},
		{"no component of its own", ".", ".", ".", pathResolved, ""},
		{"a base that is a symlink", "jump", ".", "deep/sub", pathResolved, ""},
		{"dot-dot after a symlinked directory", ".", "jump/../x", "deep/x", pathResolved, ""},
		{"dot-dot back to the root", ".", "alias/../x", "x", pathResolved, ""},
		{"a missing directory", ".", "nodir/x", "", pathMissing, ""},
		{"a missing directory behind dot-dot", ".", "nodir/../x", "", pathMissing, ""},
		{"a file where a directory is needed", ".", "file/x", "", pathBlocked, ""},
		{"dot-dot out of the workspace", ".", "../x", "", pathOutside, ""},
		{"a relative link out of the workspace", ".", "leaves/x", "", pathOutside, ""},
		{"an absolute link out of the workspace", ".", "absout/x", "", pathOutside, ""},
		{"an absolute value outside the workspace", ".", outside + "/x", "", pathOutside, ""},
		{"dot-dot out and back in by name", ".", "alias/../../" + filepath.Base(root) + "/x", "", pathUnobservable, "ambiguous"},
		{"an absolute value that re-enters by dot-dot", ".", outside + "/../" + filepath.Base(root) + "/x", "", pathUnobservable, "ambiguous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newTestWalker(t, root)
			got, res := w.resolveWorkspacePath("source", tc.base, tc.value)
			if res != tc.res || (res == pathResolved && filepath.ToSlash(got) != tc.want) {
				t.Fatalf("resolve(%q, %q) = %q, %v, want %q, %v", tc.base, tc.value, got, res, tc.want, tc.res)
			}
			reason := w.pass.unreadable["source"]
			if (tc.unreadable == "") != (reason == "") || !strings.Contains(reason, tc.unreadable) {
				t.Fatalf("source unreadable = %q, want %q", reason, tc.unreadable)
			}
		})
	}
	t.Run("a symlink passed on the way is evidence attributed to the source", func(t *testing.T) {
		w := newTestWalker(t, root)
		if _, res := w.resolveWorkspacePath("source", ".", "jump/../x"); res != pathResolved {
			t.Fatalf("resolution = %v", res)
		}
		if w.pass.entries["jump"].Kind != KindSymlink || !slices.Equal(w.pass.sources["jump"], []string{"source"}) {
			t.Fatalf("entries = %v, sources = %v", w.pass.entries, w.pass.sources)
		}
		if _, direct := w.direct["jump"]; direct {
			t.Fatal("a path found through a reference was not reached on its own")
		}
	})
	t.Run("a pass that stopped recording cannot follow a symlink", func(t *testing.T) {
		w := newTestWalker(t, root)
		w.pass.truncated = "limit exceeded"
		if _, res := w.resolveWorkspacePath("source", ".", "alias/x"); res != pathUnobservable ||
			!strings.Contains(w.pass.unreadable["source"], "symlink could not be observed") {
			t.Fatalf("resolution = %v, unreadable = %v", res, w.pass.unreadable)
		}
	})
	t.Run("a directory that cannot be inspected", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can inspect any directory")
		}
		locked := filepath.Join(root, "locked")
		if err := os.Mkdir(locked, 0o750); err != nil {
			t.Fatal(err)
		}
		// #nosec G302 -- the fixture directory must deny search access.
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			// #nosec G302 -- restores access so the temporary tree can be removed.
			_ = os.Chmod(locked, 0o700)
		})
		w := newTestWalker(t, root)
		if _, res := w.resolveWorkspacePath("source", ".", "locked/sub/x"); res != pathUnobservable ||
			!strings.Contains(w.pass.unreadable["source"], "could not be inspected") ||
			!strings.Contains(w.pass.unreadable["locked/sub"], "stat path") {
			t.Fatalf("resolution = %v, unreadable = %v", res, w.pass.unreadable)
		}
	})
}

// A linked worktree names its .git file in its metadata, and Git follows a
// symlinked directory on the way there.
func TestControlWalkerFindsALinkedWorktreeThroughASymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	symlinkFixture(t, root, "real", "alias")
	writeControlFixture(t, root, "real/wt/.git", "gitdir: x\n")
	writeControlFixture(t, root, ".git/worktrees/wt/gitdir", filepath.Join(root, "alias", "wt", ".git")+"\n")
	w := newTestWalker(t, root)
	if got := w.linkedWorktree(".git/worktrees/wt"); got != "real/wt" {
		t.Fatalf("linkedWorktree = %q, want real/wt", got)
	}
}

// A repository config that is a symlink to a file that does not exist reads as
// no configuration. A target Git could not look up is a different matter: its
// directory denies access, so what it holds was never observed.
func TestControlSurfaceReadsASymlinkedConfigWhoseFinalComponentIsMissing(t *testing.T) {
	linkConfig := func(t *testing.T, root, target string) {
		t.Helper()
		config := filepath.Join(root, ".git", "config")
		if err := os.Remove(config); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, config); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("a missing file in an existing directory", func(t *testing.T) {
		git := newControlGit(t)
		root := t.TempDir()
		git.init(t, root)
		writeControlFixture(t, root, "shared/keep", "keep")
		linkConfig(t, root, "../shared/gitconfig")
		budget := DefaultControlSurfaceBudget()
		before := controlSnapshot(t, root, budget)
		if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); diff.Changed || diff.Incomplete {
			t.Fatalf("a dangling config link names nothing to read: %+v", diff)
		}
		writeControlFixture(t, root, "shared/gitconfig", "[core]\n\thooksPath = hooks-target\n")
		expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, budget)), "shared/gitconfig")
	})
	t.Run("a directory that denies access", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can search any directory")
		}
		git := newControlGit(t)
		root := t.TempDir()
		git.init(t, root)
		writeControlFixture(t, root, "locked/gitconfig", "[core]\n")
		linkConfig(t, root, "../locked/gitconfig")
		locked := filepath.Join(root, "locked")
		// #nosec G302 -- the fixture directory must deny search access.
		if err := os.Chmod(locked, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			// #nosec G302 -- restores access so the temporary tree can be removed.
			_ = os.Chmod(locked, 0o700)
		})
		budget := DefaultControlSurfaceBudget()
		expectUnreadable(t, controlDiff(t, controlSnapshot(t, root, budget), controlSnapshot(t, root, budget)),
			".git/config", "Git config symlink target could not be observed")
	})
}

// The kernel resolves a symlink target literally. A target spelled like a Git
// home or installation path is an ordinary directory name there, so an edit to
// what it names is still an edit to a control path.
func TestControlSurfaceFollowsASymlinkTargetSpelledLikeAGitPath(t *testing.T) {
	for _, target := range []string{"~settings/envrc", "~/envrc", "%(prefix)/envrc"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			writeControlFixture(t, root, filepath.FromSlash(target), "before")
			symlinkFixture(t, root, target, ".envrc")
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); diff.Changed || diff.Incomplete {
				t.Fatalf("an unchanged workspace must read clean and complete: %+v", diff)
			}
			writeControlFixture(t, root, filepath.FromSlash(target), "after")
			expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, budget)), target)
		})
	}
	t.Run("a Git value spelled that way still names no workspace place", func(t *testing.T) {
		w := newTestWalker(t, t.TempDir())
		for _, value := range []string{"~settings/envrc", "~/envrc", "%(prefix)/envrc"} {
			if got, inside := w.workspaceTarget("source", ".", value); inside {
				t.Fatalf("workspaceTarget(%q) = %q, want no workspace place", value, got)
			}
		}
	})
	t.Run("a NUL in a link target stays invalid", func(t *testing.T) {
		w := newTestWalker(t, t.TempDir())
		if _, res := w.resolveWorkspacePath("source", ".", "a\x00b"); res == pathResolved {
			t.Fatal("a NUL byte cannot name a path")
		}
	})
}

// A trailing slash, or a trailing "." component, makes the kernel require a
// directory at the end of the path. A regular file there fails the lookup with
// ENOTDIR, so the path names nothing to observe.
func TestControlWalkerRequiresADirectoryForATrailingSlash(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, "plain/keep", "x")
	writeControlFixture(t, root, "file", "x")
	symlinkFixture(t, root, "plain", "todir")
	symlinkFixture(t, root, "file", "tofile")
	for _, tc := range []struct {
		name, value string
		want        string
		res         pathResolution
		kernelOK    bool
	}{
		{"a file by name", "file", "file", pathResolved, true},
		{"a file with a trailing slash", "file/", "", pathBlocked, false},
		{"a file with a trailing dot", "file/.", "", pathBlocked, false},
		{"a file with a trailing slash after a dot", "file/./", "", pathBlocked, false},
		{"a file with doubled trailing slashes", "file//", "", pathBlocked, false},
		{"a link to a file with a trailing slash", "tofile/", "", pathBlocked, false},
		{"a link to a file with a trailing dot", "tofile/.", "", pathBlocked, false},
		{"a link to a file by name is left for the caller", "tofile", "tofile", pathResolved, true},
		{"a directory by name", "plain", "plain", pathResolved, true},
		{"a directory with a trailing slash", "plain/", "plain", pathResolved, true},
		{"a directory with a trailing dot", "plain/.", "plain", pathResolved, true},
		{"a link to a directory with a trailing slash", "todir/", "plain", pathResolved, true},
		{"a link to a directory with a trailing dot", "todir/.", "plain", pathResolved, true},
		{"a missing name with a trailing slash", "later/", "later", pathResolved, false},
		{"a file behind dot-dot", "file/..", "", pathBlocked, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The value is joined as text: filepath.Join would clean the trailing
			// slash away, which is the part under test.
			if _, err := os.Stat(root + "/" + tc.value); (err == nil) != tc.kernelOK {
				t.Fatalf("the kernel resolves %q: err = %v, want ok = %t", tc.value, err, tc.kernelOK)
			}
			w := newTestWalker(t, root)
			got, res := w.resolveWorkspacePath("source", ".", tc.value)
			if res != tc.res || (res == pathResolved && filepath.ToSlash(got) != tc.want) {
				t.Fatalf("resolve(%q) = %q, %v, want %q, %v", tc.value, got, res, tc.want, tc.res)
			}
		})
	}
}

// A path Git cannot open because it needs a directory where a file stands is
// ignored by Git, so what the file says is not configuration. Reading it as an
// include would watch the places it names, which Git never uses.
func TestControlSurfaceIgnoresAnIncludeThatNeedsADirectory(t *testing.T) {
	for _, include := range []string{"../shared.cfg/", "../shared.cfg/."} {
		t.Run(include, func(t *testing.T) {
			git := newControlGit(t)
			root := t.TempDir()
			git.init(t, root)
			writeControlFixture(t, root, "shared.cfg", "[core]\n\thooksPath = decoy-hooks\n")
			writeControlHook(t, root, "decoy-hooks/pre-commit", "decoy")
			git.run(t, root, "config", "--local", "include.path", include)
			if out, err := git.command(t, root, "config", "--includes", "--get", "core.hooksPath"); err == nil {
				t.Fatalf("Git reads core.hooksPath = %q through %q, want no value", out, include)
			}
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			writeControlFixture(t, root, "decoy-hooks/pre-commit", "#!/bin/sh\necho changed\n")
			if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); slices.Contains(diff.Paths(), filepath.FromSlash("decoy-hooks/pre-commit")) {
				t.Fatalf("Git does not read the include, so its hooks path must not be watched: %+v", diff)
			}
		})
	}
	t.Run("the same include naming a directory is read", func(t *testing.T) {
		git := newControlGit(t)
		root := t.TempDir()
		git.init(t, root)
		writeControlFixture(t, root, "shared/keep", "keep")
		git.run(t, root, "config", "--local", "include.path", "../shared/")
		budget := DefaultControlSurfaceBudget()
		before := controlSnapshot(t, root, budget)
		writeControlFixture(t, root, "shared/keep", "changed")
		if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); diff.Incomplete {
			t.Fatalf("a directory include must still resolve: %+v", diff)
		}
	})
}

// A control symlink whose target needs a directory where a file stands does not
// resolve, as the kernel finds it.
func TestControlWalkerReportsALinkTargetThatNeedsADirectoryAsBlocked(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, "notes", "x")
	writeControlFixture(t, root, "dir/keep", "x")
	for _, tc := range []struct {
		target string
		res    pathResolution
	}{
		{"notes/", pathBlocked}, {"notes/.", pathBlocked}, {"dir/", pathResolved}, {"dir/.", pathResolved},
	} {
		t.Run(tc.target, func(t *testing.T) {
			w := newTestWalker(t, root)
			link := controlEntry{Entry: Entry{Path: ".envrc", Kind: KindSymlink, Target: tc.target}}
			if rel, res := w.resolveLinkTarget(link); res != tc.res {
				t.Fatalf("resolveLinkTarget(%q) = %q, %v, want %v", tc.target, rel, res, tc.res)
			}
		})
	}
}
