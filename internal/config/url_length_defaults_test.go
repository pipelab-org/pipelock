// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestURLLengthDefaultLoading(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"omitted", "mode: balanced\n", 8000},
		{"null", "fetch_proxy:\n  monitoring:\n    max_url_length: null\n", 8000},
		{"blank", "fetch_proxy:\n  monitoring:\n    max_url_length:\n", 8000},
		{"zero", "fetch_proxy:\n  monitoring:\n    max_url_length: 0\n", 8000},
		{"negative", "fetch_proxy:\n  monitoring:\n    max_url_length: -1\n", 8000},
		{"explicit smaller", "fetch_proxy:\n  monitoring:\n    max_url_length: 2048\n", 2048},
		{"explicit larger", "fetch_proxy:\n  monitoring:\n    max_url_length: 16000\n", 16000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadYAML(t, tc.body)
			for range 2 {
				if got := cfg.FetchProxy.Monitoring.MaxURLLength; got != tc.want {
					t.Fatalf("limit = %d, want %d", got, tc.want)
				}
				cfg.ApplyDefaults()
			}
		})
	}
	for _, value := range []string{"false", "true"} {
		t.Run(value+" is not an integer", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(path, []byte("fetch_proxy:\n  monitoring:\n    max_url_length: "+value+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := config.Load(path); err == nil {
				t.Fatal("boolean URL limit accepted")
			}
		})
	}
	if got := config.Defaults().FetchProxy.Monitoring.MaxURLLength; got != 8000 {
		t.Fatalf("no-file limit = %d, want RFC 9110's 8000 octets", got)
	}
	for _, name := range []string{"balanced", "audit"} {
		t.Run(name+" preset", func(t *testing.T) {
			cfg, err := config.Load(filepath.Join("..", "..", "configs", name+".yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.FetchProxy.Monitoring.MaxURLLength; got != 8000 {
				t.Fatalf("preset limit = %d, want 8000", got)
			}
		})
	}
}
