// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestURLTextSegmentsKnownValues(t *testing.T) {
	secret := "synthetic-" + "credential-value-42"
	path := filepath.Join(t.TempDir(), "values")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil // These tests use only loopback destinations, without DNS.
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.DLP.ScanEnv = false
	cfg.DLP.SecretsFile = path
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = nil
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)

	for _, encoding := range []struct {
		name   string
		encode func(string) string
	}{
		{"base64", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }},
		{"hex", func(s string) string { return hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(s)))) }},
	} {
		t.Run(encoding.name, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				value string
				clean bool
			}{
				{"ordinary", "ordinary", true},
				{"encoded ordinary", encoding.encode("note:ordinary"), true},
				{"configured", encoding.encode("note:" + secret), false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					raw := "http://127.0.0.1/receive#" + tc.value
					parsed, err := url.ParseRequestURI(raw)
					if err != nil {
						t.Fatal(err)
					}
					for _, value := range []string{raw, parsed.String()} {
						if got := sc.Scan(t.Context(), value); got.Allowed != tc.clean {
							t.Errorf("URL allowed=%t, want %t", got.Allowed, tc.clean)
						}
						if got := sc.ScanTextForDLP(t.Context(), value); got.Clean != tc.clean {
							t.Errorf("text clean=%t, want %t", got.Clean, tc.clean)
						}
					}
				})
			}
		})
	}
}

func TestURLTextSegmentsDLP(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "synthetic value", Regex: "SYNTHETIC_VALUE_[0-9]+", Severity: config.SeverityCritical}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name, value string
		clean       bool
	}{
		{"ordinary", "ordinary", true},
		{"encoded ordinary", "note:ordinary", true},
		{"pattern", "note:SYNTHETIC_VALUE_42", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := "https://example.com/page#" + hex.EncodeToString([]byte(tc.value))
			if got := sc.ScanTextForDLP(t.Context(), value); got.Clean != tc.clean {
				t.Errorf("text clean=%t, want %t", got.Clean, tc.clean)
			}
		})
	}
}

func TestURLTextSegmentsPatternPath(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil // These tests use only loopback destinations, without DNS.
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.DLP.ScanEnv = false
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "synthetic value", Regex: "SYNTHETIC_VALUE_[0-9]+", Severity: config.SeverityCritical}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, encoding := range []struct {
		name   string
		encode func(string) string
	}{
		{"hex", func(s string) string { return hex.EncodeToString([]byte(s)) }},
		{"hex base64", func(s string) string { return hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(s)))) }},
	} {
		t.Run(encoding.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, value string
				clean       bool
			}{
				{"ordinary", "note:ordinary", true},
				{"pattern", "note:SYNTHETIC_VALUE_42", false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					// A server-parsed request target keeps '#' in the path;
					// serializing it escapes the separator.
					parsed, err := url.ParseRequestURI("http://127.0.0.1/receive#" + encoding.encode(tc.value))
					if err != nil {
						t.Fatal(err)
					}
					if got := sc.Scan(t.Context(), parsed.String()); got.Allowed != tc.clean {
						t.Errorf("URL allowed=%t, want %t: %s", got.Allowed, tc.clean, got.Reason)
					}
				})
			}
		})
	}
}
