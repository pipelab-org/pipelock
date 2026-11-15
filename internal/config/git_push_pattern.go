// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "unicode/utf8"

// GitPushPatternWellFormed reports whether an allowed_push_repos entry is a
// complete glob. filepath.Match reports a malformed pattern only when matching
// reaches the bad part, so a probe against one value accepts an entry such as
// "host/owner/name*[". This checks the whole entry against the same grammar
// without a value: a backslash escapes one character, and a class is "[",
// an optional "^", one or more characters or lo-hi ranges, then "]".
func GitPushPatternWellFormed(pattern string) bool {
	if !utf8.ValidString(pattern) {
		return false
	}
	// classMember consumes one class character and returns the next index, or
	// -1 when the character is missing or is an unescaped "-" or "]".
	classMember := func(i int) int {
		if i >= len(pattern) || pattern[i] == '-' || pattern[i] == ']' {
			return -1
		}
		if pattern[i] == '\\' {
			i++
			if i >= len(pattern) {
				return -1
			}
		}
		_, size := utf8.DecodeRuneInString(pattern[i:])
		return i + size
	}
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
			if i >= len(pattern) {
				return false
			}
		case '[':
			i++
			if i < len(pattern) && pattern[i] == '^' {
				i++
			}
			members := 0
			for members == 0 || i >= len(pattern) || pattern[i] != ']' {
				if i = classMember(i); i < 0 {
					return false
				}
				if i < len(pattern) && pattern[i] == '-' {
					if i = classMember(i + 1); i < 0 {
						return false
					}
				}
				members++
			}
		}
	}
	return true
}
