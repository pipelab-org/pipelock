// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package gitprotect

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordsCustomPattern(t *testing.T) {
	rules := CompileDLPPatterns([]config.DLPPattern{{Name: "JWT", Regex: `[0-9]{16}`, Keywords: []string{"account"}}})
	if len(rules) != 1 || rules[0].Class != "" {
		t.Fatal("custom keyword rule took built-in class shortcut")
	}
	for _, tc := range []struct {
		text string
		want bool
	}{{"3333333333333333", false}, {"account 3333333333333333", true}} {
		if got := rules[0].regexMatches(tc.text); got != tc.want {
			t.Errorf("got %v want %v", got, tc.want)
		}
	}
}
