// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import "testing"

func TestURLInput(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"", ""},
		{"file:///project/notes.md", "file:///project/notes.md"},
		{"\x00 \tfi\nle:///project/a b.md\r \x1f", "file:///project/a b.md"},
		{"file:///project/a\x01b.md", "file:///project/a\x01b.md"},
		{"\u00a0file:///project/notes.md\u00a0", "\u00a0file:///project/notes.md\u00a0"},
	} {
		if got := URLInput(tt.in); got != tt.want {
			t.Errorf("URLInput(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHasHierarchicalScheme(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want bool
	}{
		{"https://example.com", true},
		{"custom+v1.2-test://host/path", true},
		{"FILE:///project/notes.md", true},
		{"/project/x://y/../notes.md", false},
		{`..\x://y`, false},
		{"1scheme://host", false},
		{"http:example.com", false},
		{"", false},
	} {
		if got := HasHierarchicalScheme(tt.in); got != tt.want {
			t.Errorf("HasHierarchicalScheme(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
