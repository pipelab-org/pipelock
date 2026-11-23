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
