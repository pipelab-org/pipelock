// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestModeAuditEnforcedWarnings(t *testing.T) {
	off := false
	for _, tc := range []struct {
		name    string
		mode    string
		enforce *bool
		want    bool
	}{
		{"audit enforce default", ModeAudit, nil, true},
		{"audit enforce false", ModeAudit, &off, false},
		{"balanced enforce default", ModeBalanced, nil, false},
		{"strict enforce default", ModeStrict, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Mode = tc.mode
			cfg.Enforce = tc.enforce
			got := cfg.ModeAuditEnforcedWarnings()
			if (len(got) == 1) != tc.want || len(got) > 1 {
				t.Fatalf("ModeAuditEnforcedWarnings() = %+v, want warning=%v", got, tc.want)
			}
			if tc.want && (got[0].Field != "mode" || !strings.Contains(got[0].Message, "enforce: false")) {
				t.Fatalf("warning does not name the setting that observes: %+v", got[0])
			}

			warnings, err := cfg.ValidateWithWarnings()
			if err != nil {
				t.Fatalf("ValidateWithWarnings: %v", err)
			}
			found := false
			for _, w := range warnings {
				if w.Field == "mode" && strings.Contains(w.Message, "mode: audit does not turn off blocking") {
					found = true
				}
			}
			if found != tc.want {
				t.Fatalf("startup warnings include audit notice = %v, want %v: %+v", found, tc.want, warnings)
			}
		})
	}
}

func TestModeAuditEnforcedProfileInheritance(t *testing.T) {
	off, on := false, true
	for _, tc := range []struct {
		name, mode string
		enforce    *bool
		profile    AgentProfile
		want       bool
	}{
		{"profile audit inherits default", ModeBalanced, nil, AgentProfile{Mode: ModeAudit}, true},
		{"profile audit explicit true", ModeBalanced, &off, AgentProfile{Mode: ModeAudit, Enforce: &on}, true},
		{"profile audit explicit false", ModeBalanced, nil, AgentProfile{Mode: ModeAudit, Enforce: &off}, false},
		{"inherited audit explicit true", ModeAudit, &off, AgentProfile{Enforce: &on}, true},
		{"inherited audit and false", ModeAudit, &off, AgentProfile{}, false},
		{"balanced overrides audit", ModeAudit, nil, AgentProfile{Mode: ModeBalanced}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Mode, cfg.Enforce = tc.mode, tc.enforce
			cfg.Agents = map[string]AgentProfile{"review-agent": tc.profile}
			got := cfg.ModeAuditEnforcedWarnings()
			found := false
			for _, w := range got {
				if w.Field == "agents.review-agent.mode" {
					found = true
					if !strings.Contains(w.Message, "agents.review-agent.enforce: false") {
						t.Fatalf("profile remedy must name the overriding control: %s", w.Message)
					}
				}
			}
			if found != tc.want {
				t.Fatalf("profile notice = %v, want %v; warnings=%+v", found, tc.want, got)
			}
		})
	}
}

func TestModeAuditEnforcedWarningRetainsSafetyCaveat(t *testing.T) {
	cfg := Defaults()
	cfg.Mode = ModeAudit
	warnings := cfg.ModeAuditEnforcedWarnings()
	if len(warnings) != 1 {
		t.Fatalf("warnings=%v, want one audit notice", warnings)
	}
	for _, w := range warnings {
		if !strings.Contains(w.Message, "ordinary URL") || !strings.Contains(w.Message, "still block") {
			t.Fatalf("remedy overstates observation scope: %s", w.Message)
		}
	}
}
