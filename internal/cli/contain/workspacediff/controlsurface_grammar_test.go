// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"slices"
	"testing"
)

// A configuration the parser cannot read is reported unreadable by its caller,
// so every malformed shape must return false rather than a partial read that
// would miss an include or hook path further down.
func TestScanGitConfigGrammar(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
		want   []string
		ok     bool
	}{
		{"line continuation", "[core]\n\thooksPath = a\\\nb\n", []string{"core.hookspath=ab"}, true},
		{"carriage return line continuation", "[core]\n\thooksPath = a\\\r\nb\n", []string{"core.hookspath=ab"}, true},
		{"escapes in a quoted value", "[core]\n\tk = \"a\\nb\\tc\\bd\\\"e\\\\f\"\n", []string{"core.k=a\nb\tc\bd\"e\\f"}, true},
		{"quoted value keeps its spaces", "[core]\n\tk = \" a  b \"\n", []string{"core.k= a  b "}, true},
		{"inner spaces survive unquoted", "[core]\n\tk = a  b\n", []string{"core.k=a  b"}, true},
		{"comments end a line", "[core]\n# whole line\n\tk = v ; trailing\n\tj = w # other\n", []string{"core.k=v", "core.j=w"}, true},
		{"key and section on one line", "[core] k = v\n", []string{"core.k=v"}, true},
		{"key without a value", "[core]\n\tbare\n", []string{"core.bare="}, true},
		{"conditional include subsection", "[includeIf \"gitdir:~/x\"]\n\tpath = y\n", []string{"includeif..path=y"}, true},
		{"escaped quote inside a quoted subsection", "[sub \"a\\\"]b\"]\n\tk = v\n", []string{"sub..k=v"}, true},
		{"byte order mark", "\ufeff[core]\n\tk = v\n", []string{"core.k=v"}, true},
		{"no trailing newline", "[core]\n\tk = v", []string{"core.k=v"}, true},
		{"unknown escape", "[core]\n\tk = a\\qb\n", nil, false},
		{"trailing backslash", "[core]\n\tk = a\\", nil, false},
		{"unterminated quote at line end", "[core]\n\tk = \"abc\nd\"\n", nil, false},
		{"unterminated quote at end", "[core]\n\tk = \"abc", nil, false},
		{"unterminated section header", "[core\n\tk = v\n", nil, false},
		{"key before any section", "k = v\n", nil, false},
		{"empty key", "[core]\n\t= v\n", nil, false},
		{"NUL byte", "[core]\n\tk = v\x00\n", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var visited []string
			ok := scanGitConfig(tc.config, func(section, key, value string) {
				visited = append(visited, section+"."+key+"="+value)
			})
			if ok != tc.ok {
				t.Fatalf("scanGitConfig ok = %t, want %t (visited %q)", ok, tc.ok, visited)
			}
			if tc.ok && !slices.Equal(visited, tc.want) {
				t.Fatalf("scanGitConfig visited %q, want %q", visited, tc.want)
			}
		})
	}
}

func TestGitBoolean(t *testing.T) {
	for value, want := range map[string]bool{
		"": true, "true": true, "Yes": true, "ON": true, "false": true, "no": true, "off": true,
		"0": true, "2": true, "0x10": true,
		"1_000": false, "./monitor": false, "maybe": false, "99999999999": false,
	} {
		if got := gitBoolean(value); got != want {
			t.Errorf("gitBoolean(%q) = %t, want %t", value, got, want)
		}
	}
}
