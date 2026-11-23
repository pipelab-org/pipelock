// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
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
