// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import "strings"

// ForCardText applies the credential Unicode folding without deleting table
// or line boundaries. Dots and visible separators retain their spelling.
func ForCardText(s string) string {
	if !strings.ContainsAny(s, "\t\n\r") {
		return ForDLP(s)
	}
	var out strings.Builder
	out.Grow(len(s))
	start := 0
	for i := range len(s) {
		if s[i] == '\t' || s[i] == '\n' || s[i] == '\r' {
			out.WriteString(ForDLP(s[start:i]))
			out.WriteByte(s[i])
			start = i + 1
		}
	}
	out.WriteString(ForDLP(s[start:]))
	result := out.String()
	if result == s {
		return s
	}
	return result
}
