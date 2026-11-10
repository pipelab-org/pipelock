// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestAllMatchesShippedPresetFiles keeps All in step with the preset YAML
// shipped in configs/, so a new profile cannot silently skip tests that
// iterate All.
func TestAllMatchesShippedPresetFiles(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "configs", "*.yaml"))
	if err != nil {
		t.Fatalf("glob presets: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no preset YAML found under configs/")
	}
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".yaml")
		if !slices.Contains(All, name) {
			t.Errorf("shipped preset %s is not in All", file)
		}
	}
	if len(All) != len(files) {
		t.Errorf("All has %d entries, configs/ ships %d preset files", len(All), len(files))
	}
}
