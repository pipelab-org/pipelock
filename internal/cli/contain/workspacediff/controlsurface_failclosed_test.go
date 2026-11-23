// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// unreadableReasons returns the reason recorded for each unreadable path.
func unreadableReasons(diff ControlSurfaceStatement) map[string]string {
	reasons := make(map[string]string, len(diff.Unreadable))
	for _, entry := range diff.Unreadable {
		reasons[entry.Path] = entry.Reason
	}
	return reasons
}

func expectUnreadable(t *testing.T, diff ControlSurfaceStatement, path, reason string) {
	t.Helper()
	got, named := unreadableReasons(diff)[filepath.FromSlash(path)]
	if !diff.Incomplete || !named || !strings.Contains(got, reason) {
		t.Fatalf("want an incomplete diff with %s unreadable (%q), got reason %q: %+v", path, reason, got, diff)
	}
}

// Metadata Git would act on but the walk cannot read or interpret must make the
// observation incomplete, never read as an unchanged, clean tree.
func TestControlSurfaceReportsUnreadableGitMetadata(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, root string)
		path    string
		reason  string
	}{
		{"gitfile without the pointer prefix", func(t *testing.T, root string) {
			writeControlFixture(t, root, ".git", "not a pointer\n")
		}, ".git", "invalid Git directory pointer"},
		{"gitfile with an empty target", func(t *testing.T, root string) {
			writeControlFixture(t, root, ".git", "gitdir: \n")
		}, ".git", "invalid Git directory pointer"},
		{"gitfile naming a regular file", func(t *testing.T, root string) {
			writeControlFixture(t, root, ".git", "gitdir: notadir\n")
			writeControlFixture(t, root, "notadir", "file")
		}, ".git", "Git directory target could not be observed"},
		{"gitfile naming a missing path", func(t *testing.T, root string) {
			writeControlFixture(t, root, ".git", "gitdir: missing\n")
		}, ".git", "Git directory target could not be observed"},
		{"gitfile naming a link to a missing path", func(t *testing.T, root string) {
			writeControlFixture(t, root, ".git", "gitdir: meta\n")
			symlinkFixture(t, root, "missing", "meta")
		}, ".git", "Git directory target could not be observed"},
		{"empty commondir", func(t *testing.T, root string) {
			writeControlFixture(t, root, ".git/HEAD", "ref: refs/heads/main\n")
			writeControlFixture(t, root, ".git/commondir", "")
		}, ".git/commondir", "invalid Git directory pointer"},
		{"unparsable config", func(t *testing.T, root string) {
			writeControlFixture(t, root, ".git/config", "[core\n")
		}, ".git/config", "could not parse Git configuration"},
		{"config linked to a directory", func(t *testing.T, root string) {
			writeControlFixture(t, root, "shared/keep", "keep")
			symlinkFixture(t, root, "../shared", ".git/config")
		}, ".git/config", "not a regular file"},
		{"config link chain that never ends", func(t *testing.T, root string) {
			writeControlFixture(t, root, "real.cfg", "[core]\n")
			const hops = 45
			symlinkFixture(t, root, "../l0", ".git/config")
			for i := range hops {
				target := fmt.Sprintf("l%d", i+1)
				if i == hops-1 {
					target = "real.cfg"
				}
				symlinkFixture(t, root, target, fmt.Sprintf("l%d", i))
			}
		}, ".git/config", "chain is too long"},
		{"oversize gitfile", func(t *testing.T, root string) {
			writeControlFixture(t, root, ".git", "gitdir: real\n# "+strings.Repeat("x", testControlCap)+"\n")
		}, ".git", "exceeded the control digest cap"},
		{"config linked through a regular file", func(t *testing.T, root string) {
			writeControlFixture(t, root, "real.cfg", "[core]\n")
			// An absolute target keeps the walk from resolving a dot-dot.
			symlinkFixture(t, root, root+"/real.cfg/inner", ".git/config")
		}, ".git/config", "Git config symlink target could not be observed"},
		{"link naming a place with an absolute dot-dot", func(t *testing.T, root string) {
			writeControlFixture(t, root, "b/target", "fixture")
			// Join would clean the dot-dot away; the link must keep it.
			symlinkFixture(t, root, root+"/a/../b", ".claude/link")
		}, ".claude/link", "ambiguous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.prepare(t, root)
			budget := DefaultControlSurfaceBudget()
			expectUnreadable(t, controlDiff(t, controlSnapshot(t, root, budget), controlSnapshot(t, root, budget)), tc.path, tc.reason)
		})
	}
}

// A path the snapshot cannot digest, or one that does not fit the budget, is
// reported rather than left out of a diff that then reads clean.
func TestControlSurfaceBudgetsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, root string)
		budget  func(*ControlSurfaceBudget)
		reason  string
	}{
		{"path bytes", func(t *testing.T, root string) {
			writeControlFixture(t, root, ".claude/settings.json", "{}")
		}, func(b *ControlSurfaceBudget) { b.MaxControlPathBytes = 8 }, "control path-bytes limit exceeded"},
		{"entries", func(t *testing.T, root string) {
			for _, name := range []string{"a", "b", "c", "d"} {
				writeControlFixture(t, root, ".claude/"+name, "x")
			}
		}, func(b *ControlSurfaceBudget) { b.MaxControlEntries = 2 }, "control entry limit exceeded"},
		{"directory entries that are never recorded", func(t *testing.T, root string) {
			// Git's own bookkeeping is not recorded, but listing it still costs.
			for _, name := range []string{"HEAD", "index", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD", "MERGE_MSG", "gc.log", "COMMIT_EDITMSG"} {
				writeControlFixture(t, root, ".git/"+name, "x")
			}
		}, func(b *ControlSurfaceBudget) { b.MaxControlEntries = 4 }, "control directory entry limit exceeded"},
		{"depth", func(t *testing.T, root string) {
			writeControlFixture(t, root, ".claude/a/b/c/d", "x")
		}, func(b *ControlSurfaceBudget) { b.MaxControlDepth = 3 }, "control depth limit exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.prepare(t, root)
			budget := DefaultControlSurfaceBudget()
			tc.budget(&budget)
			snap := controlSnapshot(t, root, budget)
			if !strings.Contains(snap.priority.truncated, tc.reason) {
				t.Fatalf("priority pass truncated = %q, want %q", snap.priority.truncated, tc.reason)
			}
			diff := controlDiff(t, snap, snap)
			if !diff.Incomplete || !strings.Contains(diff.IncompleteReason, tc.reason) {
				t.Fatalf("a truncated observation must be incomplete: %+v", diff)
			}
		})
	}
}

func TestControlSurfaceRejectsUnusableInputs(t *testing.T) {
	root := t.TempDir()
	good := DefaultControlSurfaceBudget()
	for name, mutate := range map[string]func(*ControlSurfaceBudget){
		"control entries":    func(b *ControlSurfaceBudget) { b.MaxControlEntries = 0 },
		"control path bytes": func(b *ControlSurfaceBudget) { b.MaxControlPathBytes = 0 },
		"control depth":      func(b *ControlSurfaceBudget) { b.MaxControlDepth = 0 },
		"nested dirs":        func(b *ControlSurfaceBudget) { b.MaxNestedDirs = 0 },
		"nested depth":       func(b *ControlSurfaceBudget) { b.MaxNestedDepth = 0 },
		"nested path bytes":  func(b *ControlSurfaceBudget) { b.MaxNestedPathBytes = 0 },
	} {
		t.Run("non-positive "+name, func(t *testing.T) {
			budget := good
			mutate(&budget)
			if _, err := SnapshotControlSurface(root, testControlCap, budget); err == nil {
				t.Fatal("a zero limit must be rejected")
			}
		})
	}
	if _, err := SnapshotControlSurface(root, 0, good); err == nil {
		t.Fatal("a zero digest cap must be rejected")
	}
	t.Run("a workspace root that is a file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		writeFile(t, file, "content")
		snap, err := SnapshotControlSurface(file, testControlCap, good)
		if err != nil || snap.problem != "workspace root is not a directory" {
			t.Fatalf("snapshot = %q, %v", snap.problem, err)
		}
		diff := controlDiff(t, snap, snap)
		if !diff.Incomplete || diff.Changed || !strings.Contains(diff.IncompleteReason, "not a directory") {
			t.Fatalf("a root that is not a directory must be incomplete without a clean claim: %+v", diff)
		}
	})
	t.Run("snapshots of different workspaces do not compare", func(t *testing.T) {
		a := controlSnapshot(t, t.TempDir(), good)
		b := controlSnapshot(t, t.TempDir(), good)
		if _, err := DiffControlSurface(a, b); err == nil {
			t.Fatal("snapshots of different roots must not compare")
		}
		if _, err := DiffControlSurface(ControlSurfaceSnapshot{}, ControlSurfaceSnapshot{}); err == nil {
			t.Fatal("zero snapshots must not compare")
		}
		other, err := SnapshotControlSurface(a.root, testControlCap+1, good)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DiffControlSurface(a, other); err == nil {
			t.Fatal("snapshots taken with different digest caps must not compare")
		}
	})
}

// A bare repository at the workspace root has no .git marker, but its hooks run
// as the operator all the same.
func TestControlSurfaceObservesABareRepositoryAtTheRoot(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, "HEAD", "ref: refs/heads/main\n")
	writeControlFixture(t, root, "config", "[core]\n\tbare = true\n")
	if err := os.MkdirAll(filepath.Join(root, "objects"), 0o750); err != nil {
		t.Fatal(err)
	}
	before := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	writeControlFixture(t, root, "hooks/pre-receive", "inert fixture")
	expectControlPath(t, controlDiff(t, before, controlSnapshot(t, root, DefaultControlSurfaceBudget())), "hooks/pre-receive")
}

// A slot that cannot be queued for discovery is reported as a partial listing,
// not skipped silently.
func TestControlSurfaceReportsAWorktreeSlotThatCannotBeQueued(t *testing.T) {
	for _, tc := range []struct {
		name   string
		budget func(*ControlSurfaceBudget)
		reason string
	}{
		{"directory count", func(b *ControlSurfaceBudget) { b.MaxNestedDirs = 1 }, "nested directory count limit exceeded"},
		{"path bytes", func(b *ControlSurfaceBudget) { b.MaxNestedPathBytes = 12 }, "nested directory path-bytes limit exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			git := newControlGit(t)
			root := t.TempDir()
			git.init(t, root)
			git.commit(t, root, "source.txt")
			git.run(t, root, "worktree", "add", "-qb", "example", filepath.Join(root, ".claude", "worktrees", "example"))
			budget := DefaultControlSurfaceBudget()
			tc.budget(&budget)
			snap := controlSnapshot(t, root, budget)
			diff := controlDiff(t, snap, snap)
			if !diff.NestedDiscoveryPartial || !strings.Contains(diff.NestedDiscoveryReason, tc.reason) {
				t.Fatalf("a slot that was not listed must be reported: %+v", diff)
			}
		})
	}
}

func TestSignBindsAControlSurfaceToTheV2Schema(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("capsule"))
	capsule := hex.EncodeToString(sum[:])
	withControls := Statement{Root: "/workspace", ControlSurface: &ControlSurfaceStatement{Added: []string{}}}
	signed, err := Sign([]Statement{withControls}, capsule, priv)
	if err != nil || signed.SchemaVersion != SchemaVersionV2 {
		t.Fatalf("Sign = %q, %v, want %s", signed.SchemaVersion, err, SchemaVersionV2)
	}
	if err := Verify(signed, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// A statement whose control surface does not match its schema version is
	// refused, in either direction, before any signature check.
	if _, err := Sign([]Statement{withControls, {Root: "/other"}}, capsule, priv); err == nil ||
		!strings.Contains(err.Error(), "control_surface does not match") {
		t.Fatalf("mixed statements must not sign: %v", err)
	}
	downgraded := signed
	downgraded.SchemaVersion = SchemaVersionV1
	if err := ValidateSchema(downgraded); err == nil || !strings.Contains(err.Error(), "control_surface does not match") {
		t.Fatalf("a control surface under schema v1 must be refused: %v", err)
	}
}

// newTestWalker builds the walker SnapshotControlSurface would, for the
// branches a real tree cannot reach on demand.
func newTestWalker(t *testing.T, root string) *controlWalker {
	t.Helper()
	handle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	mount, known := mountID(root)
	return &controlWalker{
		root: handle, rootPath: root, rootMount: mount, mountKnown: known, rootInfo: info,
		capBytes: testControlCap, budget: DefaultControlSurfaceBudget(),
		coveredTrees: make(map[string]struct{}), seenConfig: make(map[gitConfigSource]struct{}),
		seenGitDirs: make(map[gitConfigSource]struct{}), direct: make(map[string]struct{}),
		queuedTrees: make(map[string]*controlTree),
		pass: controlPass{
			entries: make(map[string]controlEntry), unreadable: make(map[string]string),
			sources: make(map[string][]string),
		},
	}
}

func observeFile(t *testing.T, w *controlWalker, rel string) controlEntry {
	t.Helper()
	entry := w.recordPath(rel)
	if entry.Kind != KindFile {
		t.Fatalf("test setup: %s was not recorded as a file: %+v", rel, entry)
	}
	return entry
}

func TestControlWalkerFailsClosedOnVanishedAndChangedEntries(t *testing.T) {
	t.Run("a metadata file that changes after it was hashed", func(t *testing.T) {
		root := t.TempDir()
		writeControlFixture(t, root, ".git/config", "[core]\n")
		w := newTestWalker(t, root)
		entry := observeFile(t, w, ".git/config")
		writeControlFixture(t, root, ".git/config", "[core]\n\tbare = true\n")
		if data, ok := w.readObserved(entry); ok || data != nil {
			t.Fatalf("a file that no longer matches its digest must not be parsed: %q", data)
		}
		if reason := w.pass.unreadable[".git/config"]; !strings.Contains(reason, "changed between hashing and parsing") {
			t.Fatalf("unreadable reason = %q", reason)
		}
	})
	t.Run("a metadata file that disappears before it is read", func(t *testing.T) {
		root := t.TempDir()
		writeControlFixture(t, root, ".git/config", "[core]\n")
		w := newTestWalker(t, root)
		entry := observeFile(t, w, ".git/config")
		if err := os.Remove(filepath.Join(root, ".git", "config")); err != nil {
			t.Fatal(err)
		}
		if _, ok := w.readObserved(entry); ok {
			t.Fatal("a vanished file cannot be read")
		}
		if reason := w.pass.unreadable[".git/config"]; !strings.Contains(reason, "open Git metadata") {
			t.Fatalf("unreadable reason = %q", reason)
		}
	})
	t.Run("an oversize metadata file is never read", func(t *testing.T) {
		w := newTestWalker(t, t.TempDir())
		if data, ok := w.readObserved(controlEntry{Entry: Entry{Path: "config", Oversize: true}}); ok || data != nil {
			t.Fatal("an oversize entry must not be read")
		}
	})
	t.Run("a path observed twice as different files", func(t *testing.T) {
		root := t.TempDir()
		writeControlFixture(t, root, ".envrc", "one")
		w := newTestWalker(t, root)
		first := w.lookup(".envrc")
		w.record(".envrc", first)
		// Both files exist at once, so the replacement has its own identity.
		writeControlFixture(t, root, ".envrc-new", "two")
		if err := os.Rename(filepath.Join(root, ".envrc-new"), filepath.Join(root, ".envrc")); err != nil {
			t.Fatal(err)
		}
		w.record(".envrc", w.lookup(".envrc"))
		if reason := w.pass.unreadable[".envrc"]; !strings.Contains(reason, "identity changed") {
			t.Fatalf("unreadable reason = %q", reason)
		}
	})
	t.Run("a path that changes while it is observed", func(t *testing.T) {
		root := t.TempDir()
		writeControlFixture(t, root, ".envrc", "one")
		w := newTestWalker(t, root)
		info := w.lookup(".envrc")
		writeControlFixture(t, root, ".envrc", "a longer replacement")
		w.recheck(".envrc", info)
		if reason := w.pass.unreadable[".envrc"]; !strings.Contains(reason, "changed during observation") {
			t.Fatalf("unreadable reason = %q", reason)
		}
	})
	t.Run("a directory that vanishes before it is listed", func(t *testing.T) {
		w := newTestWalker(t, t.TempDir())
		w.list("gone", func(string, os.DirEntry) bool { t.Fatal("nothing to visit"); return false })
		if reason := w.pass.unreadable["gone"]; !strings.Contains(reason, "directory changed before enumeration") {
			t.Fatalf("unreadable reason = %q", reason)
		}
	})
	t.Run("a listed entry that vanished", func(t *testing.T) {
		root := t.TempDir()
		writeControlFixture(t, root, ".claude/kept", "x")
		w := newTestWalker(t, root)
		kept, err := os.ReadDir(filepath.Join(root, ".claude"))
		if err != nil {
			t.Fatal(err)
		}
		w.scanTreeChild(controlTree{path: ".claude", fixed: true}, ".claude/gone", kept[0])
		if reason := w.pass.unreadable[".claude/gone"]; !strings.Contains(reason, "vanished during enumeration") {
			t.Fatalf("unreadable reason = %q", reason)
		}
	})
	t.Run("a listed entry whose type changed", func(t *testing.T) {
		root := t.TempDir()
		writeControlFixture(t, root, ".claude/file", "x")
		w := newTestWalker(t, root)
		other := t.TempDir()
		if err := os.Mkdir(filepath.Join(other, "dir"), 0o750); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(other)
		if err != nil {
			t.Fatal(err)
		}
		// The listing said a directory; the entry is now a regular file.
		w.scanTreeChild(controlTree{path: ".claude", fixed: true}, ".claude/file", entries[0])
		if reason := w.pass.unreadable[".claude/file"]; !strings.Contains(reason, "type changed during enumeration") {
			t.Fatalf("unreadable reason = %q", reason)
		}
	})
	t.Run("the unreadable path budget", func(t *testing.T) {
		w := newTestWalker(t, t.TempDir())
		w.budget.MaxControlEntries = 1
		w.unreadable("first", "reason")
		w.unreadable("second", "reason")
		if !strings.Contains(w.pass.truncated, "control unreadable path limit exceeded") || len(w.pass.unreadable) != 1 {
			t.Fatalf("truncated = %q, unreadable = %v", w.pass.truncated, w.pass.unreadable)
		}
	})
	t.Run("a link with no usable target", func(t *testing.T) {
		w := newTestWalker(t, t.TempDir())
		for _, target := range []string{"", "a\x00b"} {
			if rel, ok := w.linkTarget(controlEntry{Entry: Entry{Path: "link", Kind: KindSymlink, Target: target}}); ok {
				t.Fatalf("target %q resolved to %q", target, rel)
			}
		}
	})
}

// Configured paths the walk does not follow, because they name no workspace
// place, are out of scope rather than an observation problem.
func TestControlWalkerResolvesConfiguredPaths(t *testing.T) {
	root := t.TempDir()
	w := newTestWalker(t, root)
	for _, tc := range []struct {
		name, base, value string
		want              string
		inside            bool
	}{
		{"empty", ".", "", "", false},
		{"home relative", ".", "~/hooks", "", false},
		{"installation relative", ".", "%(prefix)/hooks", "", false},
		{"relative with no base", "", "hooks", "", false},
		{"embedded NUL", ".", "ho\x00oks", "", false},
		{"absolute path outside the workspace with a dot-dot", ".", "/outside/../hooks", "", false},
		{"current directory components", ".", "./sub/../hooks", "hooks", true},
		{"plain", "sub", "hooks", "sub/hooks", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, inside := w.workspaceTarget("source", tc.base, tc.value)
			if inside != tc.inside || (inside && filepath.ToSlash(got) != tc.want) {
				t.Fatalf("workspaceTarget(%q, %q) = %q, %t, want %q, %t", tc.base, tc.value, got, inside, tc.want, tc.inside)
			}
			if len(w.pass.unreadable) != 0 {
				t.Fatalf("a path with no workspace place is out of scope, not unreadable: %v", w.pass.unreadable)
			}
		})
	}
}

// A symlink named as a prefix of a configured path is observed, but the path
// beyond it is the link target's business and is not claimed.
func TestControlWalkerRecordsASymlinkPrefixOnly(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, "real/hooks/pre-commit", "x")
	symlinkFixture(t, root, "real", "jump")
	w := newTestWalker(t, root)
	if entry := w.recordPath("jump/hooks"); entry.Kind != "" {
		t.Fatalf("a path behind a symlink prefix must not be claimed: %+v", entry)
	}
	if entry := w.pass.entries["jump"]; entry.Kind != KindSymlink {
		t.Fatalf("the symlink prefix must be recorded as evidence: %+v", entry)
	}
}

func TestControlWalkerRecognizesABareRepositoryOnlyWithObjects(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, "headonly/HEAD", "ref: refs/heads/main\n")
	writeControlFixture(t, root, "bare/HEAD", "ref: refs/heads/main\n")
	writeControlFixture(t, root, "bare/objects/keep", "x")
	writeControlFixture(t, root, "bare/refs/keep", "x")
	w := newTestWalker(t, root)
	if w.bareRepository("headonly") {
		t.Fatal("a directory with only HEAD is not a bare repository")
	}
	if !w.bareRepository("bare") {
		t.Fatal("HEAD, objects and refs make a bare repository")
	}
	// A Git directory that cannot be observed queues nothing.
	w.scanGitDir("missing", ".", false)
	if len(w.trees) != 0 || len(w.seenGitDirs) != 0 {
		t.Fatalf("scanGitDir on a missing directory queued %d trees", len(w.trees))
	}
}

// Many repositories can share one Git directory, and each pairing is scanned for
// the configuration it names. The count is bounded, and the bound is reported
// rather than hidden.
func TestControlSurfaceBoundsGitConfigReferences(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, "common/.git/HEAD", "ref: refs/heads/main\n")
	writeControlFixture(t, root, "common/.git/config", "[include]\n\tpath = ../../shared.cfg\n")
	writeControlFixture(t, root, "shared.cfg", "[example]\n\tkey = value\n")
	for i := range 8 {
		writeControlFixture(t, root, fmt.Sprintf("r%d/.git", i), "gitdir: ../common/.git\n")
	}
	budget := DefaultControlSurfaceBudget()
	budget.MaxControlEntries = 10
	snap := controlSnapshot(t, root, budget)
	diff := controlDiff(t, snap, snap)
	if !diff.NestedDiscoveryPartial || !strings.Contains(diff.NestedDiscoveryReason, "Git config reference limit exceeded") {
		t.Fatalf("an exhausted config budget must be reported: %+v", diff)
	}
}

// A checkout in an agent worktree slot is exempt only once its metadata is shown
// to point back at this project. Where that cannot be checked, its files stay
// monitored.
func TestControlSurfaceMonitorsASlotWhoseMetadataCannotBeChecked(t *testing.T) {
	const slot = ".claude/worktrees/example"
	const script = slot + "/run.sh"
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, git testGit, root string)
		reason  string
	}{
		{"the project has no Git directory", func(t *testing.T, _ testGit, root string) {
			writeControlFixture(t, root, slot+"/.git", "gitdir: "+filepath.Join(root, ".git", "worktrees", "example")+"\n")
		}, ""},
		{"the metadata's back pointer cannot be read", func(t *testing.T, git testGit, root string) {
			git.init(t, root)
			metadata := filepath.Join(root, ".git", "worktrees", "example")
			writeControlFixture(t, root, slot+"/.git", "gitdir: "+metadata+"\n")
			writeControlFixture(t, metadata, "gitdir", filepath.Join(root, slot, ".git")+"\n# "+strings.Repeat("x", testControlCap)+"\n")
		}, "exceeded the control digest cap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			git := newControlGit(t)
			root := t.TempDir()
			tc.prepare(t, git, root)
			writeControlFixture(t, root, script, "before")
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			writeControlFixture(t, root, script, "changed")
			diff := controlDiff(t, before, controlSnapshot(t, root, budget))
			if !diff.Changed || !slices.Contains(diff.Paths(), filepath.FromSlash(script)) {
				t.Fatalf("a slot that cannot be shown to be a linked worktree stays monitored: %+v", diff)
			}
			if tc.reason != "" && !diff.Incomplete {
				t.Fatalf("an unreadable back pointer must make the observation incomplete: %+v", diff)
			}
		})
	}
}

func TestControlWalkerRecordsNothingAfterTruncation(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, ".envrc", "x")
	w := newTestWalker(t, root)
	w.pass.truncated = "limit exceeded"
	if entry := w.record(".envrc", w.lookup(".envrc")); entry.Kind != "" || len(w.pass.entries) != 0 {
		t.Fatalf("a truncated pass must not keep recording: %+v %v", entry, w.pass.entries)
	}
}
