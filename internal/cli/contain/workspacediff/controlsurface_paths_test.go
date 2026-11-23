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

func TestControlSurfaceGitAndToolPaths(t *testing.T) {
	for _, tc := range []struct {
		path   string
		before string
		after  string
	}{
		{path: ".git/commondir", after: "../../outside-metadata\n"},
		{path: ".git/config.worktree", after: "[core]\nfsmonitor = ./monitor-file\n"},
		{path: ".git/hooks/pre-commit", after: "inert fixture"},
		{path: ".git/hooks/pre-commit", before: "old fixture", after: "new fixture"},
		{path: ".git/objects/info/alternates", after: "inert fixture"},
		{path: ".git/objects/info/http-alternates", after: "inert fixture"},
		{path: ".git/rebase-merge/git-rebase-todo", after: "exec <planned command>\n"},
		{path: ".claude/settings.json", after: "{}"},
		{path: ".mcp.json", after: "{}"},
		{path: ".vscode/tasks.json", after: "{}"},
		{path: ".envrc", after: "inert fixture"},
		{path: "nested/.vscode/tasks.json", after: "{}"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			root := t.TempDir()
			if tc.before != "" {
				writeControlFixture(t, root, tc.path, tc.before)
			}
			before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			writeControlFixture(t, root, tc.path, tc.after)
			after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			expectControlPath(t, controlDiff(t, before, after), tc.path)
		})
	}
}

func TestControlSurfaceGitConfigTargets(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configPath string
		config     string
		target     string
		contents   string
	}{
		{"hook directory", ".git/config", "[CoRe]\nHooksPath = .githooks # test\n", ".githooks/pre-commit", "fixture"},
		{"metadata-relative hook directory", ".git/config", "[core]\nhooksPath = refs/custom\n", ".git/refs/custom/pre-receive", "fixture"},
		{"worktree fsmonitor", ".git/config.worktree", "[core]\nfsmonitor = ./monitor-file\n", "monitor-file", "fixture"},
		{"include path", ".git/config", "[include]\npath = ../local-config\n", "local-config", "[example]\nsetting = before\n"},
		{"conditional include", ".git/config", "[includeIf \"onbranch:future\"]\npath = \"../config with space\"\n", "config with space", "[example]\nsetting = before\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// This is an inert config fixture. Nothing invokes Git on this tree.
			root := t.TempDir()
			if tc.configPath == ".git/config.worktree" {
				writeControlFixture(t, root, ".git/config", "[extensions]\nworktreeConfig = true\n")
			}
			writeControlFixture(t, root, tc.configPath, tc.config)
			writeControlFixture(t, root, tc.target, tc.contents)
			before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			writeControlFixture(t, root, tc.target, tc.contents+"\n# updated")
			after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			expectControlPath(t, controlDiff(t, before, after), tc.target)
		})
	}
}

func TestControlSurfaceSubmoduleConfigTargetBeforeDiscovery(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, ".git/modules/dependency/HEAD", "ref: refs/heads/main\n")
	writeControlFixture(t, root, ".git/modules/dependency/config", "[core]\nworktree = ../../../dependency\nfsmonitor = ./monitor-file\n")
	const target = "dependency/monitor-file"
	writeControlFixture(t, root, target, "before")
	budget := DefaultControlSurfaceBudget()
	budget.MaxNestedDirs = 1
	before := controlSnapshot(t, root, budget)
	writeControlFixture(t, root, target, "after")
	after := controlSnapshot(t, root, budget)
	diff := controlDiff(t, before, after)
	if !diff.Changed || !diff.Incomplete || !slices.Contains(diff.Modified, filepath.FromSlash(target)) {
		t.Fatalf("priority Git scan did not report the submodule worktree target: %+v", diff)
	}
}

func TestControlSurfaceNeverExcludesVolatileSymlinks(t *testing.T) {
	for _, rel := range []string{".git/objects/pack", ".git/refs", ".git/HEAD"} {
		t.Run(rel, func(t *testing.T) {
			root := t.TempDir()
			name := filepath.FromSlash(rel)
			path := filepath.Join(root, name)
			if rel == ".git/HEAD" {
				writeControlFixture(t, root, rel, "ref: refs/heads/main\n")
			} else if err := os.MkdirAll(path, 0o750); err != nil {
				t.Fatal(err)
			}
			before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "unobserved")
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			expectControlPath(t, controlDiff(t, before, after), rel)
			if entry := after.priority.entries[name]; entry.Kind != KindSymlink || entry.Target != target {
				t.Fatalf("symlink not retained by its own kind: %+v", entry)
			}
		})
	}
}

func TestControlSurfaceKeepsObservedChangesWhenTruncated(t *testing.T) {
	for _, tc := range []struct {
		name      string
		budget    func(*ControlSurfaceBudget)
		reason    string
		wantAdded bool
	}{
		{"priority", func(b *ControlSurfaceBudget) { b.MaxControlEntries = 3 }, "control entry limit", false},
		{"nested", func(b *ControlSurfaceBudget) { b.MaxNestedDirs = 1 }, "nested directory count", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			const configPath = ".git/config"
			writeControlFixture(t, root, configPath, "[core]\nfilemode = true\n")
			writeControlFixture(t, root, ".git/hooks/fixture", "initial fixture")
			writeControlFixture(t, root, ".git/unknown", "another fixture")
			writeControlFixture(t, root, "nested/file", "ordinary file")
			budget := DefaultControlSurfaceBudget()
			tc.budget(&budget)
			before := controlSnapshot(t, root, budget)
			writeControlFixture(t, root, configPath, "[core]\nfilemode = false\n")
			writeControlFixture(t, root, ".envrc", "inert fixture")
			after := controlSnapshot(t, root, budget)
			diff := controlDiff(t, before, after)
			if !diff.Changed || !diff.Incomplete || !strings.Contains(diff.IncompleteReason, tc.reason) ||
				!slices.Contains(diff.Modified, filepath.FromSlash(configPath)) {
				t.Fatalf("want incomplete observation with config modification: %+v", diff)
			}
			if slices.Contains(diff.Added, ".envrc") != tc.wantAdded {
				t.Fatalf("want root control addition reported=%t: %+v", tc.wantAdded, diff)
			}
		})
	}
}

func TestControlSurfaceFailsClosedOnUnreadableAndRootReplacement(t *testing.T) {
	t.Run("digest cap", func(t *testing.T) {
		root := t.TempDir()
		writeControlFixture(t, root, ".mcp.json", strings.Repeat("x", testControlCap+1))
		snap := controlSnapshot(t, root, DefaultControlSurfaceBudget())
		diff := controlDiff(t, snap, snap)
		if !diff.Incomplete || len(diff.Unreadable) != 1 || diff.Unreadable[0].Path != ".mcp.json" {
			t.Fatalf("digest cap must fail closed: %+v", diff)
		}
	})
	t.Run("root inode", func(t *testing.T) {
		dir := t.TempDir()
		root := filepath.Join(dir, "workspace")
		writeControlFixture(t, root, ".envrc", "first workspace")
		before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
		if err := os.Rename(root, filepath.Join(dir, "old")); err != nil {
			t.Fatal(err)
		}
		writeControlFixture(t, root, ".envrc", "second workspace")
		after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
		diff := controlDiff(t, before, after)
		if !diff.Incomplete || !strings.Contains(diff.IncompleteReason, "identity") {
			t.Fatalf("root replacement must fail closed: %+v", diff)
		}
	})
}

func TestControlSurfaceFollowsInWorkspaceSymlinkTargets(t *testing.T) {
	link := func(t *testing.T, root, target, name string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, root string)
		edit    string
	}{
		{"hook file link", func(t *testing.T, root string) {
			writeControlFixture(t, root, "scripts/hook.sh", "before")
			link(t, root, "../../scripts/hook.sh", ".git/hooks/pre-commit")
		}, "scripts/hook.sh"},
		{"hooks directory link", func(t *testing.T, root string) {
			writeControlFixture(t, root, "githooks/pre-commit", "before")
			link(t, root, "../githooks", ".git/hooks")
		}, "githooks/pre-commit"},
		{"config file link", func(t *testing.T, root string) {
			writeControlFixture(t, root, "shared.cfg", "[core]\nfilemode = true\n")
			link(t, root, "../shared.cfg", ".git/config")
		}, "shared.cfg"},
		{"agent directory link", func(t *testing.T, root string) {
			writeControlFixture(t, root, "dot/claude/settings.json", "before")
			link(t, root, "dot/claude", ".claude")
		}, "dot/claude/settings.json"},
		{"absolute link", func(t *testing.T, root string) {
			writeControlFixture(t, root, "dot/cursor/rules", "before")
			link(t, filepath.Join(root), filepath.Join(root, "dot", "cursor"), ".cursor")
		}, "dot/cursor/rules"},
		{"link chain", func(t *testing.T, root string) {
			writeControlFixture(t, root, "real/settings.json", "before")
			link(t, root, "real", "hop")
			link(t, root, "hop", ".claude")
		}, "real/settings.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.prepare(t, root)
			before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			writeControlFixture(t, root, tc.edit, "after, now longer")
			after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			expectControlPath(t, controlDiff(t, before, after), tc.edit)
		})
	}
	t.Run("cycles and out-of-grant targets stay bounded and complete", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		writeControlFixture(t, outside, "file", "before")
		link(t, root, ".cursor", ".claude")
		link(t, root, ".claude", ".cursor")
		link(t, root, outside, ".codex")
		link(t, root, ".", ".vscode")
		link(t, root, "..", ".idea")
		before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
		writeControlFixture(t, outside, "file", "after, now longer")
		writeControlFixture(t, root, "ordinary.txt", "outside the control surface")
		after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
		if diff := controlDiff(t, before, after); diff.Changed || diff.Incomplete {
			t.Fatalf("expected a complete, clean observation: %+v", diff)
		}
	})
}

func TestControlSurfaceReportsAmbiguousDotDotLinkTargets(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, "sub/keep", "keep")
	writeControlFixture(t, root, "shared/cmds/run", "before")
	writeControlFixture(t, root, "deep/inner/keep", "keep")
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../sub/../shared/cmds", filepath.Join(root, ".claude", "cmds")); err != nil {
		t.Fatal(err)
	}
	before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	if diff := controlDiff(t, before, before); diff.Incomplete {
		t.Fatalf("a plain directory prefix resolves the same way lexically: %+v", diff)
	}
	// Replacing the prefix directory with a link makes the kernel resolve the
	// target under deep/, where a lexical walk would keep observing shared/.
	if err := os.RemoveAll(filepath.Join(root, "sub")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("deep/inner", filepath.Join(root, "sub")); err != nil {
		t.Fatal(err)
	}
	writeControlFixture(t, root, "deep/shared/cmds/run", "planted")
	after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	diff := controlDiff(t, before, after)
	if !diff.Incomplete || !strings.Contains(diff.IncompleteReason, "unreadable control paths") ||
		len(diff.Unreadable) != 1 || diff.Unreadable[0].Path != filepath.FromSlash(".claude/cmds") ||
		!strings.Contains(diff.Unreadable[0].Reason, "ambiguous") {
		t.Fatalf("want an incomplete observation naming the ambiguous link: %+v", diff)
	}
}
