// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import "testing"

// The latest version string comes from remote release metadata and is shown
// in the confirmation prompt and status lines through display.
func TestDisplayEscapesRemoteVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain version unchanged", in: "v2.8.0", want: "v2.8.0"},
		{name: "empty", in: "", want: "unknown"},
		{name: "ansi rewrite", in: "v2.8.0\x1b[2K\rv2.7.9", want: `v2.8.0\x1b[2K\rv2.7.9`},
		{name: "backspace", in: "v9.9.9\b\b\b\b\b\b2.8.0", want: `v9.9.9\x08\x08\x08\x08\x08\x082.8.0`},
		{name: "bidi", in: "v2.8.0\u202E1-cr", want: `v2.8.0\u202E1-cr`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := display(tt.in); got != tt.want {
				t.Fatalf("display(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
