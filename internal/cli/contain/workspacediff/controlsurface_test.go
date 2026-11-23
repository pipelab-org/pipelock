// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testControlCap = 1 << 20

func TestDefaultControlSurfaceBudgetMatchesContainCLIDoc(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "contain-cli.md"))
	if err != nil {
		t.Fatal(err)
	}
	b := DefaultControlSurfaceBudget()
	for _, expected := range []string{
		fmt.Sprintf("**%d control entries**", b.MaxControlEntries),
		fmt.Sprintf("**%d MiB of control paths**", b.MaxControlPathBytes>>20),
		fmt.Sprintf("**%d control path components**", b.MaxControlDepth),
		fmt.Sprintf("**%d discovery directories**", b.MaxNestedDirs),
		fmt.Sprintf("**%d discovery levels**", b.MaxNestedDepth),
		fmt.Sprintf("**%d MiB of discovery paths**", b.MaxNestedPathBytes>>20),
	} {
		if !strings.Contains(string(doc), expected) {
			t.Errorf("contain-cli.md lacks %q", expected)
		}
	}
}

type testGit struct {
	bin  string
	home string
}

func newControlGit(t *testing.T) testGit {
	t.Helper()
	bin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git is required to produce real repository metadata")
	}
	return testGit{bin: bin, home: t.TempDir()}
}

func (g testGit) command(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), g.bin, args...) // #nosec G204 -- Git and its arguments are chosen by the test.
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + g.home, "XDG_CONFIG_HOME=" + g.home,
		"GIT_ALLOW_PROTOCOL=file", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Example Developer", "GIT_AUTHOR_EMAIL=dev@example.test",
		"GIT_COMMITTER_NAME=Example Developer", "GIT_COMMITTER_EMAIL=dev@example.test",
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (g testGit) run(t *testing.T, dir string, args ...string) {
	t.Helper()
	if output, err := g.command(t, dir, args...); err != nil {
		t.Fatalf("git %q: %v\n%s", args, err, output)
	}
}

func (g testGit) init(t *testing.T, root string) {
	t.Helper()
	g.run(t, root, "init", "-q", "-b", "main")
	g.run(t, root, "config", "--local", "rerere.enabled", "true")
}

func (g testGit) commit(t *testing.T, root, name string) {
	t.Helper()
	writeControlFixture(t, root, name, "tracked file "+name)
	g.run(t, root, "add", "--", name)
	g.run(t, root, "commit", "-qm", name)
}

func writeControlFixture(t *testing.T, root, path, content string) {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func controlSnapshot(t *testing.T, root string, budget ControlSurfaceBudget) ControlSurfaceSnapshot {
	t.Helper()
	if _, ok := mountID(root); !ok {
		t.Skip("mount IDs are required for a complete control-surface observation")
	}
	snap, err := SnapshotControlSurface(root, testControlCap, budget)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func controlDiff(t *testing.T, before, after ControlSurfaceSnapshot) ControlSurfaceStatement {
	t.Helper()
	diff, err := DiffControlSurface(before, after)
	if err != nil {
		t.Fatal(err)
	}
	return diff
}

func expectControlPath(t *testing.T, result ControlSurfaceStatement, path string) {
	t.Helper()
	if !result.Changed || result.Incomplete || !slices.Contains(result.Paths(), filepath.FromSlash(path)) {
		t.Fatalf("want complete diff naming %s, got %+v", path, result)
	}
}

func TestControlSurfaceRealGitBenignOperations(t *testing.T) {
	g := newControlGit(t)
	root := t.TempDir()
	g.init(t, root)
	budget := DefaultControlSurfaceBudget()
	unchanged := func(t *testing.T, op func()) {
		t.Helper()
		before := controlSnapshot(t, root, budget)
		op()
		after := controlSnapshot(t, root, budget)
		if change := controlDiff(t, before, after); change.Changed || change.Incomplete {
			t.Fatalf("expected complete, clean observation: %+v", change)
		}
	}
	t.Run("reinitialize repository", func(t *testing.T) {
		unchanged(t, func() { g.run(t, root, "init", "-q") })
	})
	t.Run("add and commit with rerere enabled", func(t *testing.T) {
		unchanged(t, func() { g.commit(t, root, "main.txt") })
	})
	remote := t.TempDir()
	g.init(t, remote)
	g.commit(t, remote, "remote.txt")
	g.run(t, root, "remote", "add", "local", remote)
	t.Run("local fetch", func(t *testing.T) {
		unchanged(t, func() { g.run(t, root, "fetch", "-q", "local") })
	})
	t.Run("gc", func(t *testing.T) {
		unchanged(t, func() { g.run(t, root, "gc", "--prune=now") })
	})
	t.Run("stash and pop", func(t *testing.T) {
		writeControlFixture(t, root, "main.txt", "work in progress")
		unchanged(t, func() { g.run(t, root, "stash", "push", "-m", "work") })
		unchanged(t, func() { g.run(t, root, "stash", "pop") })
		g.run(t, root, "restore", "main.txt")
	})
	t.Run("branch and completed rebase", func(t *testing.T) {
		unchanged(t, func() { g.run(t, root, "checkout", "-qb", "topic") })
		g.commit(t, root, "topic.txt")
		g.run(t, root, "checkout", "-q", "main")
		g.commit(t, root, "another.txt")
		g.run(t, root, "checkout", "-q", "topic")
		unchanged(t, func() { g.run(t, root, "rebase", "main") })
	})
}

func TestControlSurfaceRealGitReftable(t *testing.T) {
	g := newControlGit(t)
	root := t.TempDir()
	out, err := g.command(t, root, "init", "-q", "-b", "main", "--ref-format=reftable")
	if err != nil {
		if strings.Contains(out, "unknown option") || strings.Contains(out, "unsupported") {
			t.Skipf("local Git lacks reftable support: %s", strings.SplitN(out, "\n", 2)[0])
		}
		t.Fatalf("git init reftable: %v: %s", err, out)
	}
	before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	g.commit(t, root, "tracked.txt")
	after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	if diff := controlDiff(t, before, after); diff.Changed || diff.Incomplete {
		t.Fatalf("reftable commit: %+v", diff)
	}
}

func TestControlSurfaceGitConflictMetadata(t *testing.T) {
	g := newControlGit(t)
	for _, op := range []string{"merge", "rebase"} {
		t.Run(op, func(t *testing.T) {
			root := t.TempDir()
			g.init(t, root)
			g.commit(t, root, "conflict.txt")
			g.run(t, root, "checkout", "-qb", "topic")
			writeControlFixture(t, root, "conflict.txt", "topic edit")
			g.run(t, root, "commit", "-qam", "topic edit")
			g.run(t, root, "checkout", "-q", "main")
			writeControlFixture(t, root, "conflict.txt", "main edit")
			g.run(t, root, "commit", "-qam", "main edit")
			g.run(t, root, "checkout", "-q", "topic")

			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			out, err := g.command(t, root, op, "main")
			if err == nil || !strings.Contains(out, "CONFLICT") {
				t.Fatalf("expected Git to stop for a conflict: %v\n%s", err, out)
			}
			paused := controlSnapshot(t, root, budget)
			diff := controlDiff(t, before, paused)
			if diff.Incomplete {
				t.Fatalf("conflict state must be readable: %+v", diff)
			}
			if op == "merge" {
				if diff.Changed {
					t.Fatalf("ordinary rerere and merge bookkeeping should remain volatile: %+v", diff)
				}
				return
			}
			const todo = ".git/rebase-merge/git-rebase-todo"
			expectControlPath(t, diff, todo)
			// Observe an inert instruction fixture. Git is never resumed.
			writeControlFixture(t, root, todo, "exec <planned command>\n")
			next := controlSnapshot(t, root, budget)
			expectControlPath(t, controlDiff(t, paused, next), todo)
		})
	}
}

func TestControlSurfaceRealGitMetadataChanges(t *testing.T) {
	g := newControlGit(t)
	tests := []struct {
		name string
		path string
		run  func(*testing.T, string)
	}{
		{"worktree", ".git/worktrees/linked/commondir", func(t *testing.T, root string) {
			g.run(t, root, "worktree", "add", "-qb", "topic", filepath.Join(t.TempDir(), "linked"))
		}},
		{"submodule", ".git/modules/dependency/config", func(t *testing.T, root string) {
			source := t.TempDir()
			g.init(t, source)
			g.commit(t, source, "dependency.txt")
			g.run(t, root, "submodule", "add", "-q", source, "dependency")
		}},
		{"config local", ".git/config", func(t *testing.T, root string) {
			g.run(t, root, "config", "--local", "branch.main.merge", "refs/heads/topic")
		}},
		{"push with upstream", ".git/config", func(t *testing.T, root string) {
			remote := t.TempDir()
			g.run(t, remote, "init", "-q", "--bare")
			g.run(t, root, "remote", "add", "local", remote)
			g.run(t, root, "push", "-qu", "local", "main")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			g.init(t, root)
			g.commit(t, root, "tracked.txt")
			before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			tc.run(t, root)
			after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			expectControlPath(t, controlDiff(t, before, after), tc.path)
		})
	}
}

func TestControlSurfaceNestedRepositories(t *testing.T) {
	g := newControlGit(t)
	for _, tc := range []struct {
		name     string
		want     string
		producer func(*testing.T, string, string)
	}{
		{"regular", "nested/.git/config", func(t *testing.T, _, dir string) {
			g.init(t, dir)
		}},
		{"separate Git directory", "nested/.git", func(t *testing.T, root, dir string) {
			g.run(t, dir, "init", "-q", "--separate-git-dir", filepath.Join(root, "metadata"))
		}},
		{"bare", "nested/config", func(t *testing.T, _, dir string) {
			g.run(t, dir, "init", "-q", "--bare")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "nested")
			if err := os.Mkdir(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			tc.producer(t, root, dir)
			after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
			expectControlPath(t, controlDiff(t, before, after), tc.want)
		})
	}
}

func TestControlSurfaceLinkedWorktreeConfigTarget(t *testing.T) {
	g := newControlGit(t)
	root := t.TempDir()
	g.init(t, root)
	g.run(t, root, "config", "--local", "extensions.worktreeConfig", "true")
	g.commit(t, root, "tracked.txt")
	g.run(t, root, "worktree", "add", "-qb", "topic", filepath.Join(root, "linked"))

	// The remaining operations observe inert data without invoking Git.
	writeControlFixture(t, root, ".git/worktrees/linked/config.worktree", "[core]\nfsmonitor = ./monitor-file\n")
	before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	writeControlFixture(t, root, "linked/monitor-file", "inert fixture")
	after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	expectControlPath(t, controlDiff(t, before, after), "linked/monitor-file")
}

func TestControlSurfaceExternalGitfile(t *testing.T) {
	g := newControlGit(t)
	root := t.TempDir()
	before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	g.run(t, root, "init", "-q", "--separate-git-dir", filepath.Join(t.TempDir(), "metadata"))
	after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	diff := controlDiff(t, before, after)
	if !diff.Changed || diff.Incomplete || !slices.Equal(diff.Paths(), []string{".git"}) {
		t.Fatalf("external gitfile should be recorded alone: %+v", diff)
	}
}

func TestControlSurfaceIndependentWorkspaceBudget(t *testing.T) {
	root := t.TempDir()
	g := newControlGit(t)
	g.init(t, root)
	fullBudget := Budget{MaxEntries: 1}
	beforeFull, err := Snapshot(root, testControlCap, fullBudget)
	if err != nil {
		t.Fatal(err)
	}
	before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	const hook = ".git/hooks/pre-commit"
	writeControlFixture(t, root, hook, "inert fixture")
	after := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	afterFull, err := Snapshot(root, testControlCap, fullBudget)
	if err != nil {
		t.Fatal(err)
	}
	full, err := Diff(beforeFull, afterFull, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !full.Incomplete || len(full.Added)+len(full.Removed)+len(full.Modified) != 0 {
		t.Fatalf("whole tree should suppress paths on budget exhaustion: %+v", full)
	}
	expectControlPath(t, controlDiff(t, before, after), hook)
}

func TestControlSurfaceDeepDiscoveryPreservesFindings(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	git.init(t, root)
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	git.init(t, nested)
	const hook = ".git/hooks/example"
	writeControlFixture(t, root, hook, "before")
	writeControlFixture(t, nested, hook, "before")
	budget := DefaultControlSurfaceBudget()
	before := controlSnapshot(t, root, budget)
	if err := os.MkdirAll(filepath.Join(root, strings.Repeat("d/", 8)), 0o750); err != nil {
		t.Fatal(err)
	}
	shallow := controlSnapshot(t, root, budget)
	if diff := controlDiff(t, before, shallow); diff.Changed || diff.Incomplete || diff.NestedDiscoveryPartial {
		t.Fatalf("eight benign levels must be clean: %+v", diff)
	}
	if err := os.MkdirAll(filepath.Join(root, strings.Repeat("d/", 70)), 0o750); err != nil {
		t.Fatal(err)
	}
	deep := controlSnapshot(t, root, budget)
	if diff := controlDiff(t, shallow, deep); diff.Changed || diff.Incomplete || !diff.NestedDiscoveryPartial ||
		!strings.Contains(diff.NestedDiscoveryReason, "depth limit exceeded at") {
		t.Fatalf("seventy benign levels must only make discovery partial: %+v", diff)
	}
	writeControlFixture(t, root, hook, "changed")
	writeControlFixture(t, nested, hook, "changed")
	writeControlFixture(t, nested, ".git/hooks/new", "new")
	diff := controlDiff(t, deep, controlSnapshot(t, root, budget))
	expectControlPath(t, diff, hook)
	expectControlPath(t, diff, "nested/"+hook)
	expectControlPath(t, diff, "nested/.git/hooks/new")
	if !diff.NestedDiscoveryPartial {
		t.Fatalf("missing nested discovery limit: %+v", diff)
	}
}

func TestControlSurfaceGitLFSObjects(t *testing.T) {
	root := t.TempDir()
	git := newControlGit(t)
	git.init(t, root)
	budget := DefaultControlSurfaceBudget()
	const source = "asset.bin"
	object := strings.Repeat("x", testControlCap+1)
	var addObject func(string)
	objectPath := func(content string) string {
		id := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
		return ".git/lfs/objects/" + id[:2] + "/" + id[2:4] + "/" + id
	}
	if _, err := git.command(t, root, "lfs", "version"); err == nil {
		git.run(t, root, "lfs", "install", "--local", "--skip-smudge")
		git.run(t, root, "lfs", "track", source)
		addObject = func(content string) {
			writeControlFixture(t, root, source, content)
			git.run(t, root, "add", "--", source)
		}
	} else {
		t.Log("Git LFS unavailable, using its documented local store layout")
		addObject = func(content string) {
			writeControlFixture(t, root, objectPath(content), content)
		}
	}
	addObject(object)
	if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(objectPath(object)))); err != nil || info.Size() != int64(len(object)) {
		t.Fatalf("missing large LFS object: %v", err)
	}
	before := controlSnapshot(t, root, budget)
	addObject(strings.Repeat("y", testControlCap+1))
	after := controlSnapshot(t, root, budget)
	if diff := controlDiff(t, before, after); diff.Changed || diff.Incomplete {
		t.Fatalf("LFS object storage must remain volatile: %+v", diff)
	}
	writeControlFixture(t, root, ".git/lfs/example", "fixture")
	expectControlPath(t, controlDiff(t, after, controlSnapshot(t, root, budget)), ".git/lfs/example")
}

func TestControlSurfaceGitCheckoutInsideFixedTree(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	git.init(t, root)
	git.commit(t, root, "source.txt")
	const checkout = ".claude/worktrees/example"
	dir := filepath.Join(root, filepath.FromSlash(checkout))
	git.run(t, root, "worktree", "add", "-qb", "example", dir)
	const hook = ".git/hooks/example"
	writeControlFixture(t, root, hook, "before")
	budget := DefaultControlSurfaceBudget()
	budget.MaxControlEntries = 256
	for i := range budget.MaxControlEntries + 1 {
		writeControlFixture(t, dir, fmt.Sprintf("source/%d.txt", i), "source")
	}
	before := controlSnapshot(t, root, budget)
	writeControlFixture(t, dir, "source.txt", strings.Repeat("x", testControlCap+1))
	after := controlSnapshot(t, root, budget)
	if diff := controlDiff(t, before, after); diff.Changed || diff.Incomplete || diff.NestedDiscoveryPartial {
		t.Fatalf("ordinary checkout content must stay outside the control surface: %+v", diff)
	}
	git.run(t, dir, "config", "extensions.worktreeConfig", "true")
	git.run(t, dir, "config", "--worktree", "core.hooksPath", ".hooks")
	writeControlFixture(t, dir, ".hooks/example", "before")
	withConfig := controlSnapshot(t, root, budget)
	expectControlPath(t, controlDiff(t, after, withConfig), ".git/worktrees/example/config.worktree")
	writeControlFixture(t, dir, ".hooks/example", "changed")
	expectControlPath(t, controlDiff(t, withConfig, controlSnapshot(t, root, budget)), checkout+"/.hooks/example")
}

// Nested discovery continues inside an agent worktree checkout, so control
// paths below its root, such as a nested project's .mcp.json or a skill under a
// nested .claude, are observed even though the checkout's source files are not.
func TestControlSurfaceWorktreeSlotNestedControlPaths(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	git.init(t, root)
	git.commit(t, root, "source.txt")
	const checkout = ".claude/worktrees/example"
	dir := filepath.Join(root, filepath.FromSlash(checkout))
	git.run(t, root, "worktree", "add", "-qb", "example", dir)
	writeControlFixture(t, dir, "src/.mcp.json", "before")
	writeControlFixture(t, dir, "src/.claude/skills/example/SKILL.md", "before")
	writeControlFixture(t, dir, "src/main.go", "before")
	budget := DefaultControlSurfaceBudget()
	before := controlSnapshot(t, root, budget)
	writeControlFixture(t, dir, "src/main.go", "changed")
	if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); diff.Changed || diff.Incomplete || diff.NestedDiscoveryPartial {
		t.Fatalf("ordinary checkout source must stay outside the control surface: %+v", diff)
	}
	for _, path := range []string{"src/.mcp.json", "src/.claude/skills/example/SKILL.md"} {
		writeControlFixture(t, dir, path, "changed "+path)
		after := controlSnapshot(t, root, budget)
		expectControlPath(t, controlDiff(t, before, after), checkout+"/"+path)
	}
}

// A workspace can hold several projects, each with its own .claude/worktrees.
// Such a checkout is found while the nested pass walks the project's .claude, so
// discovery must resume to reach the control paths below its root.
func TestControlSurfaceNestedProjectWorktreeSlotNestedControlPaths(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o750); err != nil {
		t.Fatal(err)
	}
	git.init(t, project)
	git.commit(t, project, "source.txt")
	const checkout = "project/.claude/worktrees/example"
	dir := filepath.Join(root, filepath.FromSlash(checkout))
	git.run(t, project, "worktree", "add", "-qb", "example", dir)
	writeControlFixture(t, dir, "src/.mcp.json", "before")
	writeControlFixture(t, dir, "src/.claude/skills/example/SKILL.md", "before")
	writeControlFixture(t, dir, "src/main.go", "before")
	budget := DefaultControlSurfaceBudget()
	before := controlSnapshot(t, root, budget)
	writeControlFixture(t, dir, "src/main.go", "changed")
	if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); diff.Changed || diff.Incomplete || diff.NestedDiscoveryPartial {
		t.Fatalf("ordinary checkout source must stay outside the control surface: %+v", diff)
	}
	for _, path := range []string{"src/.mcp.json", "src/.claude/skills/example/SKILL.md"} {
		writeControlFixture(t, dir, path, "changed "+path)
		expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, budget)), checkout+"/"+path)
	}
}

// A checkout found after the discovery budget is spent cannot be listed, which
// the statement says, but its root control paths were still examined, so
// removing one is reported.
func TestControlSurfaceLateWorktreeSlotWithSpentDiscoveryBudgetIsPartlyListed(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o750); err != nil {
		t.Fatal(err)
	}
	git.init(t, project)
	git.commit(t, project, "source.txt")
	const checkout = "project/.claude/worktrees/example"
	dir := filepath.Join(root, filepath.FromSlash(checkout))
	git.run(t, project, "worktree", "add", "-qb", "example", dir)
	writeControlFixture(t, dir, ".mcp.json", "before")
	writeControlFixture(t, dir, "src/.mcp.json", "before")
	// The root and the project's three entries use the whole budget before the
	// walk of the project's .claude reaches the checkout.
	budget := DefaultControlSurfaceBudget()
	budget.MaxNestedDirs = 4
	before := controlSnapshot(t, root, budget)
	if err := os.Remove(filepath.Join(dir, ".mcp.json")); err != nil {
		t.Fatal(err)
	}
	writeControlFixture(t, dir, "src/.mcp.json", "changed")
	diff := controlDiff(t, before, controlSnapshot(t, root, budget))
	if !diff.NestedDiscoveryPartial {
		t.Fatalf("a checkout that could not be listed must make discovery partial: %+v", diff)
	}
	if !slices.Contains(diff.Removed, filepath.FromSlash(checkout+"/.mcp.json")) {
		t.Fatalf("root control path of an unlisted checkout must still report its removal: %+v", diff)
	}
}

// A checkout still queued when the discovery budget runs out is partly listed
// too: skipping it as never examined would hide the removal of a control path
// at its root that the walk already observed.
func TestControlSurfaceQueuedWorktreeSlotWithSpentDiscoveryBudgetIsPartlyListed(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o750); err != nil {
		t.Fatal(err)
	}
	git.init(t, project)
	git.commit(t, project, "source.txt")
	for _, name := range []string{"first", "second"} {
		dir := filepath.Join(project, ".claude", "worktrees", name)
		git.run(t, project, "worktree", "add", "-qb", name, dir)
		writeControlFixture(t, dir, ".mcp.json", "before")
	}
	// The first checkout's listing spends the budget while the second waits.
	budget := DefaultControlSurfaceBudget()
	budget.MaxNestedDirs = 5
	before := controlSnapshot(t, root, budget)
	const removed = "project/.claude/worktrees/second/.mcp.json"
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(removed))); err != nil {
		t.Fatal(err)
	}
	diff := controlDiff(t, before, controlSnapshot(t, root, budget))
	if !diff.NestedDiscoveryPartial || !slices.Contains(diff.Removed, filepath.FromSlash(removed)) {
		t.Fatalf("a queued checkout must be partly listed and still report a removed root control path: %+v", diff)
	}
}

// A checkout anywhere in a fixed control tree other than an agent worktree slot
// keeps its working-tree files monitored: a skill or hook directory that is a
// repository can hold scripts that run as the operator.
func TestControlSurfaceCheckoutOutsideWorktreeSlotKeepsItsFiles(t *testing.T) {
	cases := map[string]struct {
		script string
		plant  func(t *testing.T, root string)
	}{
		"cloned skill": {".claude/skills/example/run.sh", func(t *testing.T, root string) {
			git := newControlGit(t)
			dir := filepath.Join(root, ".claude", "skills", "example")
			git.init(t, dir)
			git.commit(t, dir, "README.md")
		}},
		"hooks directory with a git marker": {".claude/hooks/run.sh", func(t *testing.T, root string) {
			if err := os.MkdirAll(filepath.Join(root, ".claude", "hooks", ".git"), 0o750); err != nil {
				t.Fatal(err)
			}
		}},
		"worktrees directory with an extra level": {".claude/worktrees/group/example/run.sh", func(t *testing.T, root string) {
			writeControlFixture(t, root, ".claude/worktrees/group/example/.git", "gitdir: ../../../../.git\n")
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			git := newControlGit(t)
			root := t.TempDir()
			git.init(t, root)
			writeControlFixture(t, root, tc.script, "before")
			tc.plant(t, root)
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			writeControlFixture(t, root, tc.script, "changed")
			expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, budget)), tc.script)
		})
	}
}

// Only the project's own .claude directory holds agent worktree slots. A
// .claude/worktrees path inside another monitored directory, such as a cloned
// skill or hook repository, is not where Claude Code creates checkouts, so a
// Git marker there cannot exempt its files. A nested project's own slot stays
// exempt, which keeps its source files out of the entry budget.
func TestControlSurfaceWorktreeSlotLookalikeInsideMonitoredDirectoryKeepsItsFiles(t *testing.T) {
	for _, tc := range []struct{ name, slot string }{
		{"inside a skill directory", ".claude/skills/pwn/.claude/worktrees/x"},
		{"inside a hooks directory", ".claude/hooks/.claude/worktrees/x"},
		{"inside a slot's own agent directory", ".claude/worktrees/real/.claude/worktrees/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			git := newControlGit(t)
			root := t.TempDir()
			git.init(t, root)
			if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(tc.slot), ".git"), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(root, ".claude", "worktrees", "real", ".git"), 0o750); err != nil {
				t.Fatal(err)
			}
			script := tc.slot + "/run.sh"
			writeControlFixture(t, root, script, "before")
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			writeControlFixture(t, root, script, "changed")
			expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, budget)), script)
		})
	}
	t.Run("nested project keeps its own slot exempt", func(t *testing.T) {
		git := newControlGit(t)
		root := t.TempDir()
		git.init(t, root)
		nested := filepath.Join(root, "services", "api")
		if err := os.MkdirAll(nested, 0o750); err != nil {
			t.Fatal(err)
		}
		git.init(t, nested)
		git.commit(t, nested, "main.txt")
		slot := filepath.Join(nested, ".claude", "worktrees", "example")
		git.run(t, nested, "worktree", "add", "-qb", "example", slot)
		budget := DefaultControlSurfaceBudget()
		before := controlSnapshot(t, root, budget)
		writeControlFixture(t, slot, "src/run.sh", "changed")
		if diff := controlDiff(t, before, controlSnapshot(t, root, budget)); diff.Changed || diff.Incomplete {
			t.Fatalf("a nested project's slot must stay outside the control surface: %+v", diff)
		}
	})
}

// A fixed control directory is monitored as a whole even when it carries its
// own Git marker, for example a submodule or a standalone repository for the
// agent configuration. Only checkouts found below it are limited to their Git
// metadata.
func TestControlSurfaceFixedDirectoryWithGitMarkerKeepsItsFiles(t *testing.T) {
	cases := map[string]func(t *testing.T, root string){
		"gitfile": func(t *testing.T, root string) {
			writeControlFixture(t, root, ".claude/.git", "gitdir: ../.git\n")
		},
		"gitdir": func(t *testing.T, root string) {
			if err := os.MkdirAll(filepath.Join(root, ".claude", ".git"), 0o750); err != nil {
				t.Fatal(err)
			}
		},
	}
	cases["repository"] = func(t *testing.T, root string) {
		git := newControlGit(t)
		git.init(t, filepath.Join(root, ".claude"))
		git.commit(t, filepath.Join(root, ".claude"), "history.txt")
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			git := newControlGit(t)
			root := t.TempDir()
			git.init(t, root)
			writeControlFixture(t, root, ".claude/settings.json", "before")
			writeControlFixture(t, root, ".claude/hooks/run.sh", "before")
			plant(t, root)
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			writeControlFixture(t, root, ".claude/settings.json", "changed")
			writeControlFixture(t, root, ".claude/hooks/run.sh", "changed")
			if name == "repository" {
				git.commit(t, filepath.Join(root, ".claude"), "more-history.txt")
			}
			diff := controlDiff(t, before, controlSnapshot(t, root, budget))
			expectControlPath(t, diff, ".claude/settings.json")
			expectControlPath(t, diff, ".claude/hooks/run.sh")
			if name == "repository" {
				for _, path := range diff.Paths() {
					if strings.HasPrefix(path, ".claude/.git/") && !strings.HasSuffix(path, "/config") {
						t.Errorf("volatile repository metadata reported: %s", path)
					}
				}
			}
		})
	}
}

// Discovery that runs out of budget while listing a repository's directory
// still observed that repository's Git directory and fixed paths. A hook added
// there must be reported even when the same directory was cut off at both
// endpoints, for example by a pre-existing wide directory.
func TestControlSurfaceReportsAdditionsInsideAPartiallyListedRepository(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	git.init(t, root)
	nested := filepath.Join(root, "wide")
	if err := os.Mkdir(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	git.init(t, nested)
	budget := DefaultControlSurfaceBudget()
	budget.MaxNestedDirs = 50
	for i := range budget.MaxNestedDirs + 30 {
		writeControlFixture(t, nested, fmt.Sprintf("file-%d", i), "ordinary file")
	}
	before := controlSnapshot(t, root, budget)
	writeControlFixture(t, nested, ".git/hooks/pre-commit", "inert fixture")
	writeControlFixture(t, nested, ".claude/settings.json", "inert fixture")
	diff := controlDiff(t, before, controlSnapshot(t, root, budget))
	if !diff.NestedDiscoveryPartial || diff.Incomplete {
		t.Fatalf("want partial nested discovery only: %+v", diff)
	}
	expectControlPath(t, diff, "wide/.git/hooks/pre-commit")
	expectControlPath(t, diff, "wide/.claude/settings.json")
}

func TestControlPassDiscoveredCoversOnlyWhatWasExamined(t *testing.T) {
	pass := controlPass{
		undiscovered: map[string]struct{}{"pending": {}},
		partlyListed: map[string]struct{}{"wide": {}},
	}
	for path, want := range map[string]bool{
		"wide/.git/hooks/pre-commit":     true,
		"wide/.claude/settings.json":     true,
		"wide/.mcp.json":                 true,
		"wide/sub/.claude/settings.json": false,
		"wide/sub/.git/hooks/pre-commit": false,
		"wide/.gitignore":                false,
		"wide":                           false,
		"pending/.git/config":            false,
		"pending":                        false,
		"other/.git/config":              true,
		".envrc":                         true,
	} {
		if got := pass.discovered(filepath.FromSlash(path)); got != want {
			t.Errorf("discovered(%q) = %t, want %t", path, got, want)
		}
	}
}

// A bare repository can sit at a fixed path, for example a repository
// initialized inside the agent configuration directory. Its configuration
// still names hook directories that run when Git is used there.
func TestControlSurfaceBareRepositoryAtFixedPathFollowsItsConfig(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	git.init(t, root)
	bare := filepath.Join(root, ".claude")
	if err := os.Mkdir(bare, 0o750); err != nil {
		t.Fatal(err)
	}
	git.run(t, bare, "init", "-q", "--bare", ".")
	git.run(t, bare, "config", "core.hooksPath", "../tools/hooks")
	writeControlFixture(t, root, "tools/hooks/pre-commit", "before")
	writeControlFixture(t, root, ".claude/settings.json", "before")
	writeControlFixture(t, root, ".claude/commands/run.md", "before")
	budget := DefaultControlSurfaceBudget()
	before := controlSnapshot(t, root, budget)
	writeControlFixture(t, root, "tools/hooks/pre-commit", "changed")
	writeControlFixture(t, root, ".claude/settings.json", "changed")
	writeControlFixture(t, root, ".claude/commands/run.md", "changed")
	diff := controlDiff(t, before, controlSnapshot(t, root, budget))
	expectControlPath(t, diff, "tools/hooks/pre-commit")
	// The directory's own agent files are not Git internals and are never filtered.
	expectControlPath(t, diff, ".claude/settings.json")
	expectControlPath(t, diff, ".claude/commands/run.md")
}

// Discovery keeps queued directory paths in memory. Their count is bounded,
// but a few hundred thousand names of 255 bytes under a deep chain are not, so
// the queue has a path-bytes budget as the whole-workspace snapshot does.
func TestControlSurfaceDiscoveryBoundsQueuedPathBytes(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	git.init(t, root)
	const hook = ".git/hooks/example"
	writeControlFixture(t, root, hook, "before")
	budget := DefaultControlSurfaceBudget()
	budget.MaxNestedPathBytes = 256
	before := controlSnapshot(t, root, budget)
	for i := range 20 {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("dir-%02d-%s", i, strings.Repeat("x", 40))), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeControlFixture(t, root, hook, "changed")
	diff := controlDiff(t, before, controlSnapshot(t, root, budget))
	if diff.Incomplete || !diff.NestedDiscoveryPartial || !strings.Contains(diff.NestedDiscoveryReason, "path-bytes limit exceeded at") {
		t.Fatalf("want partial nested discovery from the path-bytes limit: %+v", diff)
	}
	expectControlPath(t, diff, hook)
	budget.MaxNestedPathBytes = 0
	if _, err := SnapshotControlSurface(root, testControlCap, budget); err == nil {
		t.Fatal("a zero discovery path budget must be rejected")
	}
}

// Where discovery stopped before reaching a nested repository at one endpoint,
// its Git directory is absent from that snapshot because it was never examined,
// not because it changed. Neither an addition nor a removal may be inferred.
func TestControlSurfaceInfersNothingFromUnexaminedNestedDirectories(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	git.init(t, root)
	for _, nested := range []string{"a", "b/c"} {
		dir := filepath.Join(root, filepath.FromSlash(nested))
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		git.init(t, dir)
		writeControlFixture(t, dir, ".git/hooks/example", "fixture")
	}
	full := DefaultControlSurfaceBudget()
	// The root holds .git, a and b: the entry budget ends exactly after its
	// listing, so every queued directory is left unexamined.
	stopped := full
	stopped.MaxNestedDirs = 3
	complete := controlSnapshot(t, root, full)
	cutOff := controlSnapshot(t, root, stopped)
	for name, pair := range map[string][2]ControlSurfaceSnapshot{
		"unexamined at end":   {complete, cutOff},
		"unexamined at start": {cutOff, complete},
	} {
		t.Run(name, func(t *testing.T) {
			diff := controlDiff(t, pair[0], pair[1])
			if !diff.NestedDiscoveryPartial || diff.Incomplete || diff.Changed {
				t.Fatalf("an unexamined directory proves no change: %+v", diff)
			}
		})
	}
}

func TestControlSurfaceDiscoveryDirectoryCountLimit(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	budget := DefaultControlSurfaceBudget()
	budget.MaxNestedDirs = 3 // the root and two of the three directories
	snap := controlSnapshot(t, root, budget)
	diff := controlDiff(t, snap, snap)
	if diff.Incomplete || !diff.NestedDiscoveryPartial || !strings.Contains(diff.NestedDiscoveryReason, "directory count limit exceeded at") {
		t.Fatalf("want partial discovery from the directory count limit: %+v", diff)
	}
}

// An agent worktree checkout must report the same control path changes as the
// same project placed as an ordinary nested repository. Only its source files
// are exempt, and a plain nested project never reports those either, so the two
// layouts must agree path for path. This compares observations across layouts
// rather than against a fixed expectation list.
func TestControlSurfaceWorktreeSlotMatchesPlainNestedProject(t *testing.T) {
	edits := []string{
		"src/main.go",
		".mcp.json",
		".claude/settings.json",
		"src/.mcp.json",
		"src/.envrc",
		"src/.claude/skills/example/SKILL.md",
		"deep/a/b/c/.vscode/tasks.json",
		"vendor/lib/.git/hooks/pre-commit",
		"vendor/lib/.claude/commands/run.md",
	}
	type layout struct {
		name  string
		build func(t *testing.T, git testGit, root string) string
	}
	mkdir := func(t *testing.T, dir string) {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	worktree := func(t *testing.T, git testGit, project, rel string) string {
		mkdir(t, project)
		git.init(t, project)
		git.commit(t, project, "README.md")
		dir := filepath.Join(project, filepath.FromSlash(rel))
		git.run(t, project, "worktree", "add", "-qb", "example", dir)
		return dir
	}
	layouts := []layout{
		{"plain nested project", func(t *testing.T, git testGit, root string) string {
			git.init(t, root)
			dir := filepath.Join(root, "project")
			mkdir(t, dir)
			git.init(t, dir)
			git.commit(t, dir, "README.md")
			return dir
		}},
		{"root worktree slot", func(t *testing.T, git testGit, root string) string {
			return worktree(t, git, root, ".claude/worktrees/example")
		}},
		{"nested project worktree slot", func(t *testing.T, git testGit, root string) string {
			git.init(t, root)
			return worktree(t, git, filepath.Join(root, "project"), ".claude/worktrees/example")
		}},
	}
	observed := make(map[string][]string, len(layouts))
	for _, l := range layouts {
		git := newControlGit(t)
		root := t.TempDir()
		dir := l.build(t, git, root)
		mkdir(t, filepath.Join(dir, "vendor", "lib"))
		git.init(t, filepath.Join(dir, "vendor", "lib"))
		for _, path := range edits {
			writeControlFixture(t, dir, path, "before")
		}
		prefix, err := filepath.Rel(root, dir)
		if err != nil {
			t.Fatal(err)
		}
		budget := DefaultControlSurfaceBudget()
		before := controlSnapshot(t, root, budget)
		var seen []string
		for _, path := range edits {
			writeControlFixture(t, dir, path, "changed "+path)
			diff := controlDiff(t, before, controlSnapshot(t, root, budget))
			if diff.Incomplete || diff.NestedDiscoveryPartial {
				t.Fatalf("%s: %s: incomplete observation %+v", l.name, path, diff)
			}
			if slices.Contains(diff.Paths(), filepath.ToSlash(filepath.Join(prefix, path))) {
				seen = append(seen, path)
			}
			writeControlFixture(t, dir, path, "before")
		}
		observed[l.name] = seen
	}
	want := observed[layouts[0].name]
	if slices.Contains(want, "src/main.go") || len(want) != len(edits)-1 {
		t.Fatalf("plain nested project observed %q, want every control path and no source file", want)
	}
	for _, l := range layouts[1:] {
		if got := observed[l.name]; !slices.Equal(got, want) {
			t.Errorf("%s observed %q, plain nested project observed %q", l.name, got, want)
		}
	}
}

func TestControlSurfaceClassifiesPathsAcrossPasses(t *testing.T) {
	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	const name = "settings"
	old := controlEntry{mode: 0o600}
	updated := controlEntry{mode: 0o644}
	before := ControlSurfaceSnapshot{
		root: root, rootInfo: info,
		priority: controlPass{entries: map[string]controlEntry{name: old}},
		nested:   controlPass{entries: map[string]controlEntry{name: old}},
	}
	after := ControlSurfaceSnapshot{
		root: root, rootInfo: info,
		nested: controlPass{entries: map[string]controlEntry{name: updated}},
	}
	for _, diff := range []ControlSurfaceStatement{controlDiff(t, before, after), controlDiff(t, after, before)} {
		if len(diff.Added) != 0 || len(diff.Removed) != 0 || !slices.Equal(diff.Modified, []string{name}) {
			t.Errorf("expected one modification, got %+v", diff)
		}
	}
}

// A path found only through a nested repository's configuration, such as an
// included file or a hook directory, is examined only when discovery reaches
// that repository. A snapshot whose discovery missed it proves neither that the
// path was added nor that it was removed.
func TestControlSurfaceInfersNothingFromReferencesOfUnexaminedRepositories(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	git.init(t, root)
	nested := filepath.Join(root, "x", "y", "a")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	git.init(t, nested)
	git.run(t, nested, "config", "--local", "include.path", "../../../../shared.cfg")
	git.run(t, nested, "config", "--local", "core.hooksPath", "../../../hk")
	writeControlFixture(t, root, "shared.cfg", "[example]\n\tkey = value\n")
	writeControlFixture(t, root, "hk/pre-commit", "before")
	full := DefaultControlSurfaceBudget()
	// Depth 2 lists x and y, but y's child a is never queued, so a's Git
	// directory is not examined while the root's own directories are.
	shallow := full
	shallow.MaxNestedDepth = 2
	complete := controlSnapshot(t, root, full)
	writeControlFixture(t, root, "shared.cfg", "[example]\n\tkey = changed\n")
	writeControlFixture(t, root, "hk/pre-commit", "changed")
	changed := controlSnapshot(t, root, full)
	diff := controlDiff(t, complete, changed)
	expectControlPath(t, diff, "shared.cfg")
	expectControlPath(t, diff, "hk/pre-commit")
	cutOff := controlSnapshot(t, root, shallow)
	for name, pair := range map[string][2]ControlSurfaceSnapshot{
		"unexamined at end":   {complete, cutOff},
		"unexamined at start": {cutOff, complete},
	} {
		t.Run(name, func(t *testing.T) {
			diff := controlDiff(t, pair[0], pair[1])
			if !diff.NestedDiscoveryPartial || diff.Incomplete || diff.Changed {
				t.Fatalf("a repository that was not examined proves no change to what it references: %+v", diff)
			}
		})
	}
}

// A path can be recorded by the root pass at one endpoint and by the nested
// pass at the other. Neither pass compared it, so each would report it as
// added or removed, and dropping both would hide a modification.
func TestControlSurfaceComparesAPathObservedByDifferentPassesAtEachEndpoint(t *testing.T) {
	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	const name = "settings"
	entry := func(digest string) controlEntry {
		return controlEntry{Entry: Entry{Path: name, Kind: KindFile, Digest: digest}, mode: 0o600}
	}
	for _, tc := range []struct {
		name     string
		before   controlEntry
		after    controlEntry
		modified bool
	}{
		{"content changed", entry("old"), entry("new"), true},
		{"content unchanged", entry("same"), entry("same"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := ControlSurfaceSnapshot{
				root: root, rootInfo: info,
				priority: controlPass{entries: map[string]controlEntry{name: tc.before}},
			}
			after := ControlSurfaceSnapshot{
				root: root, rootInfo: info,
				nested: controlPass{entries: map[string]controlEntry{name: tc.after}},
			}
			for _, diff := range []ControlSurfaceStatement{controlDiff(t, before, after), controlDiff(t, after, before)} {
				if len(diff.Added) != 0 || len(diff.Removed) != 0 {
					t.Errorf("a path observed at both endpoints is never added or removed: %+v", diff)
				}
				if got := slices.Equal(diff.Modified, []string{name}); got != tc.modified {
					t.Errorf("modified = %t, want %t: %+v", got, tc.modified, diff)
				}
			}
		})
	}
}

// A fixed control path that discovery reaches on its own stays covered even when
// a repository also references it. Discovery visits the referencing repository
// first here, so the reference is how the path was first recorded. A snapshot
// that never examined that repository still examined the path's directory, so
// deleting the file is reported.
func TestControlSurfaceReportsRemovalOfADirectlyMonitoredPathAlsoReferenced(t *testing.T) {
	git := newControlGit(t)
	root := t.TempDir()
	git.init(t, root)
	// The repository's long name cannot be queued under the cut-off snapshot's
	// path budget, while the directories leading to the target can.
	nested := filepath.Join(root, "x", strings.Repeat("r", 40))
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	git.init(t, nested)
	git.run(t, nested, "config", "--local", "include.path", "../../../m/n/o/.mcp.json")
	const target = "m/n/o/.mcp.json"
	writeControlFixture(t, root, target, "[example]\n\tkey = before\n")
	full := DefaultControlSurfaceBudget()
	narrow := full
	narrow.MaxNestedPathBytes = 16
	complete := controlSnapshot(t, root, full)
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(target))); err != nil {
		t.Fatal(err)
	}
	cutOff := controlSnapshot(t, root, narrow)
	diff := controlDiff(t, complete, cutOff)
	if !diff.NestedDiscoveryPartial || !slices.Contains(diff.Removed, filepath.FromSlash(target)) {
		t.Fatalf("a deleted control file in an examined directory must be reported: %+v", diff)
	}
}

// A fixed control directory is monitored whole, including a bare repository
// inside it. Git's volatile-file filter applies to a repository's own metadata
// elsewhere, but here refs and the other files Git rewrites are part of a
// directory the agent configuration lives in.
func TestControlSurfaceBareRepositoryInsideFixedDirectoryIsMonitoredWhole(t *testing.T) {
	for _, tc := range []struct{ name, bare, edit string }{
		{"refs", ".claude/cache", "refs/heads/planted"},
		{"info refs", ".claude/cache", "info/refs"},
		{"head", ".claude/cache", "HEAD"},
		{"at the fixed directory", ".claude", "refs/heads/planted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			git := newControlGit(t)
			root := t.TempDir()
			git.init(t, root)
			dir := filepath.Join(root, filepath.FromSlash(tc.bare))
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			git.run(t, dir, "init", "-q", "--bare", ".")
			writeControlFixture(t, dir, tc.edit, "ref: refs/heads/before\n")
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			writeControlFixture(t, dir, tc.edit, "ref: refs/heads/changed\n")
			expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, budget)), tc.bare+"/"+tc.edit)
		})
	}
}
