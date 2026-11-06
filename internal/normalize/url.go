// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"regexp"
	"strings"
)

// URLInput applies WHATWG basic URL parser input preprocessing: remove leading
// and trailing C0 controls or space, then remove ASCII tab, LF and CR throughout.
// It is a URL view, not a transformation for literal filesystem paths.
func URLInput(value string) string {
	value = strings.TrimFunc(value, func(r rune) bool { return r <= 0x20 })
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, value)
}

// RFC 3986 section 3.1 defines the leading scheme syntax. This is the shared
// hierarchical URI detector; a :// inside a path segment is not a scheme.
var hierarchicalScheme = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)

// HasHierarchicalScheme reports whether value starts with a scheme:// prefix.
func HasHierarchicalScheme(value string) bool {
	return hierarchicalScheme.MatchString(value)
}
