// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package plsentry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestScrubberNeedsRestart(t *testing.T) {
	t.Setenv("SENTRY_DSN", "")
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "custom", Regex: "CobaltHazelnut[0-9]{5}"}}
	enabled := true
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN
	c, err := initClient(cfg, "test", &mockTransport{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if (*Client)(nil).ScrubberNeedsRestart(cfg) || (&Client{}).ScrubberNeedsRestart(cfg) || c.ScrubberNeedsRestart(nil) || c.ScrubberNeedsRestart(cfg) {
		t.Fatal("absent or matching scrubber reported drift")
	}
	for _, tc := range []struct {
		name string
		edit func(*config.Config)
		want bool
	}{
		{"same regex, different name", func(c *config.Config) { c.DLP.Patterns[0].Name = "renamed" }, false},
		{"different regex", func(c *config.Config) { c.DLP.Patterns[0].Regex = "OtherHazelnut[0-9]{5}" }, true},
		{"pattern removed", func(c *config.Config) { c.DLP.Patterns = nil }, true},
		{"no destination exemption consumer", func(c *config.Config) { c.DLP.Patterns[0].ExemptDomains = []string{"api.vendor.example"} }, false},
		{"unreadable source", func(c *config.Config) { c.DLP.SecretsFile = filepath.Join(t.TempDir(), "absent") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := cfg.Clone()
			tc.edit(next)
			if got := c.ScrubberNeedsRestart(next); got != tc.want {
				t.Fatalf("drift=%t want=%t", got, tc.want)
			}
		})
	}
	if (&Client{enabled: true}).ScrubberNeedsRestart(cfg) != true {
		t.Fatal("missing active scrubber reported agreement")
	}
	path := filepath.Join(t.TempDir(), "values.txt")
	if err := os.WriteFile(path, []byte("CobaltHazelnut48372\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.DLP.SecretsFile = path
	c, err = initClient(cfg, "test", &mockTransport{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if c.ScrubberNeedsRestart(cfg) {
		t.Fatal("fresh client disagrees with its file secrets")
	}
	if err := os.WriteFile(path, []byte("OtherHazelnut48372\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !c.ScrubberNeedsRestart(cfg) {
		t.Fatal("same-path file rotation was hidden")
	}
}
