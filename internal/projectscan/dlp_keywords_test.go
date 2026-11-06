// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package projectscan

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordsCustomPattern(t *testing.T) {
	rules, err := compileDLPPatternsFrom([]config.DLPPattern{{Name: "account", Regex: `[0-9]{16}`, Keywords: []string{"account"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		text string
		want bool
	}{{"3333333333333333", false}, {"account 3333333333333333", true}} {
		if got := rules[0].matches(tc.text); got != tc.want {
			t.Errorf("got %v want %v", got, tc.want)
		}
	}
}
