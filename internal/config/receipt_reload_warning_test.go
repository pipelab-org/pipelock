// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"strings"
	"testing"
)

func TestDetectorInputChanges(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Config)
		want []string
	}{
		{"unchanged", func(*Config) {}, nil},
		{"dlp.patterns", func(c *Config) {
			c.DLP.Patterns = append(c.DLP.Patterns, DLPPattern{Name: "sample", Regex: "sample"})
		}, []string{"dlp.patterns"}},
		{"dlp.scan_env", func(c *Config) { c.DLP.ScanEnv = !c.DLP.ScanEnv }, []string{"dlp.scan_env"}},
		{"dlp.secrets_file", func(c *Config) { c.DLP.SecretsFile = "new-file" }, []string{"dlp.secrets_file"}},
		{"canary_tokens", func(c *Config) { c.CanaryTokens.Enabled = !c.CanaryTokens.Enabled }, []string{"canary_tokens"}},
		{"unrelated", func(c *Config) { c.KillSwitch.APIToken = "other-token" }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := Defaults()
			next := old.Clone()
			tc.edit(next)
			if got := DetectorInputChanges(old, next); !slices.Equal(got, tc.want) {
				t.Fatalf("DetectorInputChanges = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectorInputChangesIgnoresExemptDomains(t *testing.T) {
	old := Defaults()
	if len(old.DLP.Patterns) == 0 {
		t.Fatal("defaults carry no DLP patterns")
	}
	next := old.Clone()
	next.DLP.Patterns[0].ExemptDomains = append(next.DLP.Patterns[0].ExemptDomains, "docs.vendor.example")
	if got := DetectorInputChanges(old, next); len(got) != 0 {
		t.Fatalf("exempt_domains change reported as detector input: %v", got)
	}
}

// Startup detector notices must not enter ValidateReload: strict mode refuses
// any reload that carries a warning, so a notice there would refuse reloads
// that only add canary tokens.
func TestValidateReloadOmitsDetectorNotices(t *testing.T) {
	old := Defaults()
	old.FlightRecorder.Enabled = true
	old.FlightRecorder.Redact = true
	next := old.Clone()
	next.CanaryTokens.Enabled = !old.CanaryTokens.Enabled
	for _, w := range ValidateReload(old, next) {
		if w.Field == "flight_recorder" || strings.Contains(w.Message, "receipt content check") {
			t.Fatalf("unexpected detector notice in reload warnings: %+v", w)
		}
	}
}

func TestSecretsFileReloadMessage(t *testing.T) {
	old := Defaults()
	old.DLP.SecretsFile = "old-file"
	next := old.Clone()
	next.DLP.SecretsFile = "new-file"
	for _, w := range ValidateReload(old, next) {
		if w.Field == "dlp.secrets_file" {
			if !strings.Contains(w.Message, "request scanner reloads secrets") || strings.Contains(w.Message, "secrets will be reloaded") {
				t.Fatalf("secrets_file message = %q", w.Message)
			}
			return
		}
	}
	t.Fatal("missing secrets_file reload message")
}
