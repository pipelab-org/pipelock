// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestGitPushPatternWellFormed(t *testing.T) {
	t.Parallel()
	const host = "git.vendor.example/acme/"
	tests := []struct {
		pattern string
		want    bool
	}{
		{host + "project", true},
		{"git.vendor.example/*", true},
		{host + "pr?ject*", true},
		{host + "p[a-c]x", true},
		{host + "p[^a-c0-9]x", true},
		{host + `p\[x`, true},
		{host + `p[\]]x`, true},
		{host + "private*[", false},
		{host + "p[", false},
		{host + "p[]", false},
		{host + "p[^]", false},
		{host + "p[a-]", false},
		{host + "p[-a]", false},
		{host + "p[a", false},
		{host + `p\`, false},
		{host + "p[a-c", false},
		{host + "p\xff", false},
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			t.Parallel()
			if got := GitPushPatternWellFormed(tc.pattern); got != tc.want {
				t.Fatalf("GitPushPatternWellFormed(%q) = %t, want %t", tc.pattern, got, tc.want)
			}
			// A pattern this accepts must never make the matcher report a
			// bad pattern, whatever value it is applied to.
			if tc.want {
				for _, value := range []string{tc.pattern, host + "project", host + "pax", ""} {
					if _, err := filepath.Match(tc.pattern, value); errors.Is(err, filepath.ErrBadPattern) {
						t.Fatalf("accepted pattern %q is bad for value %q", tc.pattern, value)
					}
				}
			}
		})
	}
}

func TestValidateRejectsMalformedPushRepoPattern(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.GitProtection.Enabled = true
	cfg.GitProtection.AllowedPushRepos = []string{"git.vendor.example/acme/private*["}
	if err := cfg.Validate(); err == nil {
		t.Fatal("a push repo entry with an unclosed class was accepted")
	}
}
