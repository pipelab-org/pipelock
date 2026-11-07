// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"path/filepath"
	"slices"
	"testing"
)

// A file tool can carry its target under a key that is not a recognized
// pathname field. Local identity resolution must still follow that value when
// it contains a space, as it does for a space-free value under the same key.
func TestLocalPathIdentity_WhitespaceValueUnderUnrecognizedKey(t *testing.T) {
	for _, tt := range []struct{ name, file string }{
		{"space-free name", "notes.txt"},
		{"name with a space", "my notes.txt"},
		{"name with a tab", "my\tnotes.txt"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newLocalPathFixture(t)
			f.write(t, filepath.Join(f.home, ".profile"))
			alias := filepath.Join(f.ws, tt.file)
			f.link(t, filepath.Join(f.home, ".profile"), alias)
			v := checkPath(f.policy(true), testWriteTool, "workspace_entry", alias)
			if !slices.Contains(v.Rules, testShellProfileRule) {
				t.Fatalf("symlink alias under an unrecognized key was not resolved: %+v", v)
			}
		})
	}
}
