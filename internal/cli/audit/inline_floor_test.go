// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/projectscan"
)

func TestAuditCoreFloorTakesPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, content, pattern string
	}{
		{"configured core", "AK" + "IA" + strings.Repeat("A", 16), "AWS Access ID"},
		{"core only", `"type": "service_` + `account"`, "GCP Service Account Key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "settings.yaml")
			// A non-core match precedes the core pattern in the default registry.
			nonCore := "sk-" + "proj-" + strings.Repeat("x", 24)
			var expectedScore *int
			for _, mode := range []struct {
				name, marker string
				config       bool
			}{
				{name: "no suppression"},
				{name: "bare inline", marker: " # pipelock:ignore"},
				{name: "named inline", marker: " # pipelock:ignore OpenAI API Key"},
				{name: "config suppression", config: true},
			} {
				t.Run(mode.name, func(t *testing.T) {
					if err := os.WriteFile(path, []byte(nonCore+" "+tc.content+mode.marker+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					cmd := testRoot()
					var out strings.Builder
					cmd.SetOut(&out)
					cmd.SetErr(&strings.Builder{})
					args := []string{"audit", dir, "--json"}
					if mode.config {
						configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
						data := "suppress:\n  - rule: OpenAI API Key\n    path: settings.yaml\n"
						if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
							t.Fatal(err)
						}
						args = append(args, "--config", configPath)
					}
					cmd.SetArgs(args)
					if err := cmd.Execute(); err != nil {
						t.Fatal(err)
					}
					var report projectscan.Report
					if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
						t.Fatal(err)
					}
					var matches []projectscan.Finding
					for _, f := range report.Findings {
						if f.File == "settings.yaml" {
							matches = append(matches, f)
						}
					}
					if len(matches) != 1 || matches[0].Pattern != tc.pattern {
						t.Fatalf("got %+v, want one %s finding", matches, tc.pattern)
					}
					if expectedScore == nil {
						score := report.ScoreWith
						expectedScore = &score
					} else if report.ScoreWith != *expectedScore {
						t.Fatalf("suppression changed core penalty: got %d, want %d", report.ScoreWith, *expectedScore)
					}
				})
			}
		})
	}
}
