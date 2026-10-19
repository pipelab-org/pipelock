//go:build enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Elastic-2.0

package enterprise

import (
	"reflect"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMergeAgentProfilePreservesScannerLapse(t *testing.T) {
	for _, optOut := range []bool{false, true} {
		t.Run(map[bool]string{false: "last expired path retains shipped defaults", true: "explicit empty path remains opted out"}[optOut], func(t *testing.T) {
			base := config.Defaults()
			past := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
			base.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{Host: "api.vendor.example", PathPrefix: "/files/", Expires: past}}
			if optOut {
				base.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{}
			}
			base.WebSocketProxy.ContentEntropyExclusions = []config.EntropyHostExclusion{{Host: "api.vendor.example", Expires: past}}
			if _, err := base.LapseExpiredScannerExceptions(time.Now()); err != nil {
				t.Fatal(err)
			}
			for _, profile := range []*config.AgentProfile{nil, {Mode: config.ModeBalanced}} {
				merged, err := MergeAgentProfile(base, profile)
				if err != nil {
					t.Fatal(err)
				}
				merged.ApplyDefaults()
				if !reflect.DeepEqual(merged.LapsedScannerExceptionWarnings(), base.LapsedScannerExceptionWarnings()) {
					t.Fatal("profile discarded private lapse diagnostics")
				}
				if !reflect.DeepEqual(merged.FetchProxy.Monitoring.PathEntropyExclusions, base.FetchProxy.Monitoring.PathEntropyExclusions) {
					t.Fatal("profile changed path-default intent")
				}
				warnings, err := merged.ValidateWithWarnings()
				if err != nil {
					t.Fatal(err)
				}
				found := 0
				for _, w := range warnings {
					for _, lapse := range base.LapsedScannerExceptionWarnings() {
						if w == lapse {
							found++
						}
					}
				}
				if found != len(base.LapsedScannerExceptionWarnings()) {
					t.Fatal("profile validation lost retained warnings")
				}
			}
		})
	}
}
