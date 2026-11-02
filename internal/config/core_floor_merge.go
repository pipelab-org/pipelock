// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "strings"

// WithCoreDLPFloor returns patterns plus each core floor DLP pattern that is
// not already present with the same name, expression, and validator. The proxy scanner
// applies the core floor whatever the configuration holds, so an offline scan
// (git scan-diff, project audit) must not depend on the configured list to
// include it.
func WithCoreDLPFloor(patterns []DLPPattern) []DLPPattern {
	out := append([]DLPPattern(nil), patterns...)
	for _, core := range CoreDLPPatterns() {
		present := false
		for _, p := range patterns {
			if strings.EqualFold(p.Name, core.Name) && p.Regex == core.Regex && p.Validator == core.Validator {
				present = true
				break
			}
		}
		if !present {
			out = append(out, core)
		}
	}
	return out
}
