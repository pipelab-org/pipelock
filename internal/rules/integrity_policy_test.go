// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestStrictIntegrityError(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		override   bool
		result     *LoadResult
		deny       bool
	}{
		{"nil result", config.ModeStrict, false, nil, false},
		{"clean", config.ModeStrict, false, &LoadResult{}, false},
		{"integrity", config.ModeStrict, false, &LoadResult{Errors: []BundleError{{Name: "installed", Reason: "hash mismatch", Class: BundleErrorClassIntegrity}}}, true},
		{"unknown class", config.ModeStrict, false, &LoadResult{Errors: []BundleError{{Name: "installed", Reason: "unknown", Class: BundleErrorClass("future")}}}, true},
		{"unclassified", config.ModeStrict, false, &LoadResult{Errors: []BundleError{{Name: "installed", Reason: "unknown"}}}, true},
		{"availability", config.ModeStrict, false, &LoadResult{Errors: []BundleError{{Name: "optional", Reason: "unavailable", Class: BundleErrorClassAvailability}}}, false},
		{"override", config.ModeStrict, true, &LoadResult{Errors: []BundleError{{Name: "installed", Class: BundleErrorClassIntegrity}}}, false},
		{"balanced", config.ModeBalanced, false, &LoadResult{Errors: []BundleError{{Name: "installed", Class: BundleErrorClassIntegrity}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Mode = tc.mode
			cfg.Rules.AllowDegraded = tc.override
			err := StrictIntegrityError(cfg, tc.result)
			if (err != nil) != tc.deny {
				t.Fatalf("error=%v want denial=%v", err, tc.deny)
			}
			if tc.deny && (!strings.Contains(err.Error(), "installed") || !strings.Contains(err.Error(), "rules.allow_degraded")) {
				t.Fatalf("missing remedy: %v", err)
			}
		})
	}
}
