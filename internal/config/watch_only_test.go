// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestWatchOnlyBooleanLifecycle(t *testing.T) {
	cases := []struct {
		name, yaml     string
		watch, enforce bool
	}{
		{"omitted", "{}", false, true},
		{"null", "watch_only: null", false, true},
		{"blank", "watch_only:", false, true},
		{"false", "watch_only: false", false, true},
		{"true", "watch_only: true", true, false},
		{"overrides enforce", "watch_only: true\nenforce: true", true, false},
		{"legacy audit", "enforce: false", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.WatchOnly != tc.watch || cfg.EnforceEnabled() != tc.enforce {
				t.Fatalf("watch=%t enforce=%t, want %t/%t", cfg.WatchOnly, cfg.EnforceEnabled(), tc.watch, tc.enforce)
			}
			clone := cfg.Clone()
			if clone.WatchOnly != tc.watch || clone.EnforceEnabled() != tc.enforce {
				t.Fatal("clone changed effective mode")
			}
			clone.WatchOnly = !cfg.WatchOnly
			if cfg.WatchOnly != tc.watch {
				t.Fatal("clone mutated source")
			}
		})
	}
}

func TestWatchOnlyReloadWarnings(t *testing.T) {
	for _, before := range []bool{false, true} {
		for _, after := range []bool{false, true} {
			old, updated := Defaults(), Defaults()
			old.WatchOnly, updated.WatchOnly = before, after
			found := false
			for _, w := range ValidateReload(old, updated) {
				if w.Field == "watch_only" {
					found = true
					if w.Disposition != ReloadWarningDispositionAdvisory {
						t.Fatal("explicit watch-only transition rejected")
					}
				}
				if w.Field == "enforce" {
					t.Fatal("watch-only misreported as legacy enforce change")
				}
			}
			if found != (before != after) {
				t.Fatalf("%t -> %t warning=%t", before, after, found)
			}
		}
	}
	old, updated := Defaults(), Defaults()
	off := false
	updated.Enforce = &off
	for _, w := range ValidateReload(old, updated) {
		if w.Field == "enforce" && w.Disposition != ReloadWarningDispositionAdvisory {
			return
		}
	}
	t.Fatal("legacy enforcement downgrade lost rejection")
}

func TestWatchOnlyPolicyHash(t *testing.T) {
	off := Defaults()
	on := off.Clone()
	on.WatchOnly = true
	if on.CanonicalPolicyHash() == off.CanonicalPolicyHash() {
		t.Fatal("watch-only missing from signed policy identity")
	}
	restored := on.Clone()
	restored.WatchOnly = false
	if restored.CanonicalPolicyHash() != off.CanonicalPolicyHash() {
		t.Fatal("disabling watch-only did not restore policy hash")
	}
}

func TestWatchOnlySuppressesMisleadingAuditEnforcementNotice(t *testing.T) {
	cfg := Defaults()
	cfg.Mode, cfg.WatchOnly = ModeAudit, true
	on := true
	cfg.Agents = map[string]AgentProfile{"test": {Mode: ModeAudit, Enforce: &on}}
	if warnings := cfg.ModeAuditEnforcedWarnings(); len(warnings) != 0 {
		t.Fatalf("watch-only claimed audit enforces: %+v", warnings)
	}
}
