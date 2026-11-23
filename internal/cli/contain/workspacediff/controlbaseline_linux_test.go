// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func reloadControlBaseline(t *testing.T, before ControlSurfaceSnapshot) ControlSurfaceSnapshot {
	t.Helper()
	data, err := EncodeControlBaseline(before)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	after, err := DecodeControlBaseline(f, before.root)
	if err != nil {
		t.Fatal(err)
	}
	return after
}

func TestControlBaselineRoundTrip(t *testing.T) {
	root := t.TempDir()
	newControlGit(t).init(t, root)
	const hook = ".git/hooks/pre-commit"
	const link = ".claude/link"
	const nested = "nested/.claude/settings.json"
	const raw = ".claude/raw-\xff"
	writeControlFixture(t, root, hook, "inert fixture")
	writeControlFixture(t, root, nested, "before")
	writeControlFixture(t, root, raw, "raw filename")
	if err := os.Symlink("raw-\xff", filepath.Join(root, link)); err != nil {
		t.Fatal(err)
	}
	budget := DefaultControlSurfaceBudget()
	before := controlSnapshot(t, root, budget)
	loaded := reloadControlBaseline(t, before)
	if got := controlDiff(t, loaded, before); got.Incomplete || got.Changed || got.NestedDiscoveryPartial {
		t.Fatalf("round trip changed the observation: %+v", got)
	}
	if err := os.Chmod(filepath.Join(root, hook), 0o700); err != nil { // #nosec G302 -- executable hook mode is the regression fixture.
		t.Fatal(err)
	}
	writeControlFixture(t, root, nested, "after")
	if err := os.Remove(filepath.Join(root, link)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("raw-\xfe", filepath.Join(root, link)); err != nil {
		t.Fatal(err)
	}
	after := controlSnapshot(t, root, budget)
	diff := controlDiff(t, loaded, after)
	for _, path := range []string{hook, link, nested} {
		expectControlPath(t, diff, path)
	}
}

func TestControlBaselineDiscoveryRoundTrip(t *testing.T) {
	root := t.TempDir()
	git := newControlGit(t)
	git.init(t, root)
	nested := filepath.Join(root, "wide")
	if err := os.Mkdir(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	git.init(t, nested)
	budget := DefaultControlSurfaceBudget()
	budget.MaxNestedDirs = 50
	budget.MaxNestedDepth = 2
	for i := range budget.MaxNestedDirs + 30 {
		writeControlFixture(t, nested, fmt.Sprintf("file-%d", i), "ordinary file")
	}
	writeControlFixture(t, root, "deep/sub/leaf/file", "ordinary file")
	before := controlSnapshot(t, root, budget)
	loaded := reloadControlBaseline(t, before)
	if len(before.nested.undiscovered) == 0 || len(before.nested.partlyListed) == 0 {
		t.Fatalf("fixture must exercise both discovery maps: %+v", before.nested)
	}
	if !maps.Equal(before.nested.undiscovered, loaded.nested.undiscovered) ||
		!maps.Equal(before.nested.partlyListed, loaded.nested.partlyListed) {
		t.Fatal("discovery coverage did not survive the round trip")
	}
	writeControlFixture(t, nested, ".claude/settings.json", "inert fixture")
	writeControlFixture(t, root, "deep/sub/leaf/.envrc", "inert fixture")
	after := controlSnapshot(t, root, budget)
	diff := controlDiff(t, loaded, after)
	if expected := controlDiff(t, before, after); !reflect.DeepEqual(diff, expected) {
		t.Fatalf("loaded diff = %+v, live diff = %+v", diff, expected)
	}
	if !diff.NestedDiscoveryPartial || diff.Incomplete {
		t.Fatalf("want partial nested discovery only: %+v", diff)
	}
	expectControlPath(t, diff, "wide/.claude/settings.json")
}

func TestControlBaselineIdentityChange(t *testing.T) {
	root := filepath.Join(t.TempDir(), "project")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	budget := DefaultControlSurfaceBudget()
	current := controlSnapshot(t, root, budget)
	beforeBoot := current
	beforeBoot.identity.BootID = "00000000-0000-0000-0000-000000000000"
	bootDiff := controlDiff(t, reloadControlBaseline(t, beforeBoot), current)
	if !bootDiff.Incomplete || !strings.Contains(bootDiff.IncompleteReason, "host rebooted") {
		t.Fatalf("boot mismatch must be incomplete: %+v", bootDiff)
	}

	loaded := reloadControlBaseline(t, current)
	if err := os.Rename(root, root+"-previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	diff := controlDiff(t, loaded, controlSnapshot(t, root, budget))
	if !diff.Incomplete || !strings.Contains(diff.IncompleteReason, "root identity") {
		t.Fatalf("root replacement must be incomplete: %+v", diff)
	}
}

// A replacement preview is only a review if it names what changed. A reboot or
// a replaced root makes the comparison incomplete, but the control paths are
// still compared, so an operator accepting the new observation sees them.
func TestControlBaselineIdentityChangeStillNamesChangedPaths(t *testing.T) {
	const hook = ".git/hooks/pre-commit"
	for _, tc := range []struct {
		name   string
		change func(*ControlSurfaceSnapshot)
		reason string
	}{
		{name: "reboot", reason: "host rebooted", change: func(s *ControlSurfaceSnapshot) {
			s.identity.BootID = "00000000-0000-0000-0000-000000000000"
		}},
		{name: "root inode", reason: "root identity", change: func(s *ControlSurfaceSnapshot) {
			s.identity.Ino++
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			newControlGit(t).init(t, root)
			writeControlFixture(t, root, ".envrc", "before")
			budget := DefaultControlSurfaceBudget()
			baseline := controlSnapshot(t, root, budget)
			tc.change(&baseline)
			loaded := reloadControlBaseline(t, baseline)
			writeControlFixture(t, root, ".envrc", "after")
			writeControlFixture(t, root, hook, "inert fixture")
			diff, err := CompareControlBaseline(loaded, controlSnapshot(t, root, budget))
			if err != nil {
				t.Fatal(err)
			}
			if !diff.Incomplete || !strings.Contains(diff.IncompleteReason, tc.reason) {
				t.Fatalf("identity change must stay incomplete: %+v", diff)
			}
			for _, path := range []string{".envrc", hook} {
				if !slices.Contains(diff.Paths(), filepath.FromSlash(path)) {
					t.Fatalf("%s hidden by the identity change: %+v", path, diff)
				}
			}
		})
	}
}

// A persisted baseline must give the same verdict as the observation it was
// written from. The diff reads which repositories referenced a path, so those
// references have to survive the round trip.
func TestControlBaselineKeepsReferencesOfUnexaminedRepositories(t *testing.T) {
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
	shallow := full
	shallow.MaxNestedDepth = 2
	complete := controlSnapshot(t, root, full)
	cutOff := controlSnapshot(t, root, shallow)
	for name, pair := range map[string][2]ControlSurfaceSnapshot{
		"unexamined at end":   {complete, cutOff},
		"unexamined at start": {cutOff, complete},
	} {
		t.Run(name, func(t *testing.T) {
			live := controlDiff(t, pair[0], pair[1])
			loaded, err := CompareControlBaseline(reloadControlBaseline(t, pair[0]), pair[1])
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(live, loaded) {
				t.Fatalf("loaded baseline disagrees with the observation it came from:\nlive   %+v\nloaded %+v", live, loaded)
			}
			if !loaded.NestedDiscoveryPartial || loaded.Incomplete || loaded.Changed {
				t.Fatalf("a repository that was not examined proves no change to what it references: %+v", loaded)
			}
		})
	}
}

// The baseline codec lists each observed field by hand, so a field added to the
// observation without a matching wire field would silently stop surviving the
// round trip. Adding one must come with a decision here.
func TestControlBaselineCodecCoversEveryObservedField(t *testing.T) {
	fields := func(v any) []string {
		typ := reflect.TypeOf(v)
		names := make([]string, 0, typ.NumField())
		for i := range typ.NumField() {
			names = append(names, typ.Field(i).Name)
		}
		slices.Sort(names)
		return names
	}
	for name, tc := range map[string]struct {
		got  any
		want []string
	}{
		"snapshot": {ControlSurfaceSnapshot{}, []string{"capBytes", "identity", "nested", "priority", "problem", "root"}},
		"pass": {controlPass{}, []string{
			"discoveryLimit", "entries", "partlyListed", "sources", "truncated", "undiscovered", "unreadable",
		}},
		"entry":        {controlEntry{}, []string{"Entry", "info", "mode"}},
		"entry fields": {Entry{}, []string{"Digest", "Kind", "ModTime", "Oversize", "Path", "Size", "Target"}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := fields(tc.got); !slices.Equal(got, tc.want) {
				t.Fatalf("observed fields changed; encode the new field in controlbaseline.go and list it here: %v", got)
			}
		})
	}
}

// A symlink passed while resolving a configured path is recorded as evidence
// attributed to the file that named it. The loaded baseline must read each
// change to those links, and to what they lead to, exactly as the snapshot it
// was written from does. Retargeting or removing the link, or editing the file
// it reaches, are the changes an agent can make without touching the config.
func TestControlBaselineKeepsPathsResolvedThroughSymlinks(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, root string)
		path string
	}{
		{name: "retarget the link", path: "alias", edit: func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "alias")); err != nil {
				t.Fatal(err)
			}
			symlinkFixture(t, root, "other", "alias")
		}},
		{name: "remove the link", path: "alias", edit: func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "alias")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "edit what the link reaches", path: "real/hooks/pre-commit", edit: func(t *testing.T, root string) {
			writeControlHook(t, root, "real/hooks/pre-commit", "edited")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			git := newControlGit(t)
			root := t.TempDir()
			git.init(t, root)
			symlinkFixture(t, root, "real", "alias")
			writeControlHook(t, root, "real/hooks/pre-commit", "original")
			writeControlHook(t, root, "other/hooks/pre-commit", "original")
			git.run(t, root, "config", "--local", "core.hooksPath", "alias/hooks")
			budget := DefaultControlSurfaceBudget()
			before := controlSnapshot(t, root, budget)
			if len(before.priority.sources["alias"]) == 0 && len(before.nested.sources["alias"]) == 0 {
				t.Fatalf("fixture must record the link as a referenced path: %+v", before.priority.sources)
			}
			loaded := reloadControlBaseline(t, before)
			tc.edit(t, root)
			after := controlSnapshot(t, root, budget)
			live := controlDiff(t, before, after)
			fromDisk, err := CompareControlBaseline(loaded, after)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(live, fromDisk) {
				t.Fatalf("loaded baseline disagrees with the observation it came from:\nlive   %+v\nloaded %+v", live, fromDisk)
			}
			expectControlPath(t, fromDisk, tc.path)
		})
	}
}

// The audit command checks the root's path and then the snapshot opens it
// again, so a swap between the two reaches the snapshot unchecked. The swapped
// tree here holds byte-identical control files; only the root identity tells
// it apart, and that must keep the comparison from reading clean.
func TestControlBaselineRootSwappedForALinkIsNotClean(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "project", "ws")
	decoy := filepath.Join(base, "decoy", "ws")
	for _, dir := range []string{root, decoy} {
		writeControlFixture(t, dir, ".envrc", "same")
	}
	budget := DefaultControlSurfaceBudget()
	loaded := reloadControlBaseline(t, controlSnapshot(t, root, budget))
	if err := os.Rename(filepath.Join(base, "project"), filepath.Join(base, "project-moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "decoy"), filepath.Join(base, "project")); err != nil {
		t.Fatal(err)
	}
	diff, err := CompareControlBaseline(loaded, controlSnapshot(t, root, budget))
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Incomplete || !strings.Contains(diff.IncompleteReason, "root identity") {
		t.Fatalf("a swapped root must never read clean: %+v", diff)
	}
}

// A control symlink whose literal target is spelled like a Git home path, or
// ends in a slash that demands a directory, is resolved by rules a snapshot
// applies while it is observed. A baseline read back from disk must reach the
// same verdict as the snapshot it came from, unchanged and after each edit of
// the target.
func TestControlBaselineKeepsLinkTargetSpellingsAcrossReload(t *testing.T) {
	type edit struct {
		name  string
		apply func(t *testing.T, root string)
	}
	remove := func(path string) func(*testing.T, string) {
		return func(t *testing.T, root string) {
			if err := os.RemoveAll(filepath.Join(root, path)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		name   string
		target string
		setup  func(t *testing.T, root string)
		edits  []edit
	}{
		{
			name: "in-workspace target spelled like a Git home path", target: "~settings/envrc",
			setup: func(t *testing.T, root string) { writeControlFixture(t, root, "~settings/envrc", "before") },
			edits: []edit{
				{name: "edit the target", apply: func(t *testing.T, root string) { writeControlFixture(t, root, "~settings/envrc", "after") }},
				{name: "remove the target", apply: remove("~settings/envrc")},
				{name: "retarget the link", apply: func(t *testing.T, root string) {
					remove(".envrc")(t, root)
					symlinkFixture(t, root, "other", ".envrc")
				}},
			},
		},
		{
			name: "directory with a trailing slash", target: "dir/",
			setup: func(t *testing.T, root string) { writeControlFixture(t, root, "dir/x", "before") },
			edits: []edit{
				{name: "edit a file in the directory", apply: func(t *testing.T, root string) { writeControlFixture(t, root, "dir/x", "after") }},
				{name: "replace the directory by a file", apply: func(t *testing.T, root string) {
					remove("dir")(t, root)
					writeControlFixture(t, root, "dir", "now a file")
				}},
				{name: "remove the directory", apply: remove("dir")},
			},
		},
		{
			name: "regular file with a trailing slash", target: "file/",
			setup: func(t *testing.T, root string) { writeControlFixture(t, root, "file", "before") },
			edits: []edit{
				{name: "edit the file", apply: func(t *testing.T, root string) { writeControlFixture(t, root, "file", "after") }},
				{name: "replace the file by a directory", apply: func(t *testing.T, root string) {
					remove("file")(t, root)
					writeControlFixture(t, root, "file/x", "now a directory")
				}},
				{name: "remove the file", apply: remove("file")},
			},
		},
	} {
		for _, e := range tc.edits {
			t.Run(tc.name+"/"+e.name, func(t *testing.T) {
				root := t.TempDir()
				tc.setup(t, root)
				symlinkFixture(t, root, tc.target, ".envrc")
				budget := DefaultControlSurfaceBudget()
				before := controlSnapshot(t, root, budget)
				loaded := reloadControlBaseline(t, before)
				compare := func(label string) ControlSurfaceStatement {
					t.Helper()
					after := controlSnapshot(t, root, budget)
					live := controlDiff(t, before, after)
					fromDisk, err := CompareControlBaseline(loaded, after)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(live, fromDisk) {
						t.Fatalf("%s: loaded baseline disagrees with the observation it came from:\nlive   %+v\nloaded %+v", label, live, fromDisk)
					}
					return fromDisk
				}
				if got := compare("unchanged"); got.Changed || got.Incomplete {
					t.Fatalf("an unchanged workspace must read clean and complete: %+v", got)
				}
				e.apply(t, root)
				got := compare("after the edit")
				if !got.Changed && !got.Incomplete {
					t.Fatalf("an edit to what the link names must be reported after %q: %+v", e.name, got)
				}
			})
		}
	}
}

// Inode and device numbers use all 64 bits on some filesystems, and a JSON
// reader that goes through float64 rounds anything above 2^53. A rounded
// identity would make a replaced root compare as the recorded one.
func TestControlBaselineKeepsFullWidthIdentityNumbers(t *testing.T) {
	root := t.TempDir()
	writeControlFixture(t, root, ".envrc", "x")
	snap := controlSnapshot(t, root, DefaultControlSurfaceBudget())
	snap.identity.Dev, snap.identity.Ino, snap.identity.Mount = 1<<63+1, 1<<62+12345, 1<<60+7
	loaded := reloadControlBaseline(t, snap)
	if loaded.identity != snap.identity {
		t.Fatalf("identity changed across the baseline file: %+v, want %+v", loaded.identity, snap.identity)
	}
}
