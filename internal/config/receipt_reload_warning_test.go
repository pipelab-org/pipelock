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
		{"canary_tokens", func(c *Config) {
			c.CanaryTokens.Enabled = true
			c.CanaryTokens.Tokens = []CanaryToken{{Name: "sample", Value: "sample-canary-value"}}
		}, []string{"canary_tokens"}},
		{"seed_phrase_detection", func(c *Config) {
			disabled := false
			c.SeedPhraseDetection.Enabled = &disabled
		}, []string{"seed_phrase_detection"}},
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

func TestDetectorInputChangesCanaryAndSeedNormalization(t *testing.T) {
	old := Defaults()
	old.CanaryTokens.Enabled = true
	old.CanaryTokens.Tokens = []CanaryToken{{Name: "sample", Value: "Sample-Canary-Value", EnvVar: "SAMPLE_CANARY"}}
	next := Defaults()
	next.CanaryTokens.Enabled = true
	next.CanaryTokens.Tokens = []CanaryToken{{Name: "sample", Value: "sample-canary-value", EnvVar: "OTHER_CANARY"}}
	if got := DetectorInputChanges(old, next); len(got) != 0 {
		t.Fatalf("case and env binding reported as detector input: %v", got)
	}
	disabled := Defaults()
	disabled.CanaryTokens.Enabled = false
	disabled.CanaryTokens.Tokens = []CanaryToken{{Name: "sample", Value: "sample-canary-value"}}
	edited := Defaults()
	edited.CanaryTokens.Enabled = false
	edited.CanaryTokens.Tokens = []CanaryToken{{Name: "sample", Value: "another-canary-value"}}
	if got := DetectorInputChanges(disabled, edited); len(got) != 0 {
		t.Fatalf("disabled token edit reported: %v", got)
	}

	seedOff := Defaults()
	off := false
	seedOff.SeedPhraseDetection.Enabled = &off
	seedOff.SeedPhraseDetection.MinWords = 24
	sameOff := seedOff.Clone()
	sameOff.SeedPhraseDetection.MinWords = 12
	if got := DetectorInputChanges(seedOff, sameOff); len(got) != 0 {
		t.Fatalf("disabled seed min_words reported: %v", got)
	}
	on := true
	enabled := seedOff.Clone()
	enabled.SeedPhraseDetection.Enabled = &on
	if got := DetectorInputChanges(seedOff, enabled); !slices.Equal(got, []string{"seed_phrase_detection"}) {
		t.Fatalf("enabling seed detection = %v", got)
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
