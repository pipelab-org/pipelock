// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDoctorMCPTaintDiagnostics_NoLiveCoverageClaim(t *testing.T) {
	for _, body := range []string{"", "taint: {enabled: false}\n", "session_profiling: {enabled: true}\n"} {
		t.Run(body, func(t *testing.T) {
			cfg, err := config.LoadBytes([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			report := buildDoctorReport(cfg, "test")
			for _, d := range cfg.MCPTaintDiagnostics() {
				found := false
				for _, c := range report.Checks {
					if c.Name == d.Field {
						found = true
						if c.Reachable || c.Enforcing || c.Configured != cfg.Taint.Enabled || c.Detail != d.Message {
							t.Fatalf("configuration confused with live coverage: %+v", c)
						}
					}
				}
				if !found {
					t.Fatalf("doctor omitted %s", d.Field)
				}
			}
			var text strings.Builder
			for _, c := range report.Checks {
				text.WriteString(c.Detail)
			}
			if !strings.Contains(text.String(), "cross-request taint protection is NOT active") {
				t.Fatal("doctor omitted anonymous limit")
			}
		})
	}
}

func TestDoctorMCPTaintDiagnostics_AllInformational(t *testing.T) {
	for _, tc := range []struct {
		name             string
		taint, profiling bool
	}{{"disabled", false, false}, {"recording", true, true}, {"missing_recorder", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Taint.Enabled = tc.taint
			cfg.SessionProfiling.Enabled = tc.profiling
			for _, c := range buildDoctorReport(cfg, "test").Checks {
				if !strings.HasPrefix(c.Name, "taint.mcp_") {
					continue
				}
				want := doctorStatusInfo
				if c.Status != want {
					t.Errorf("%s status=%s want=%s", c.Name, c.Status, want)
				}
			}
		})
	}
}

func TestDoctorMCPTaintDiagnostics_BaseCleanExitZero(t *testing.T) {
	for _, taint := range []bool{false, true} {
		t.Run(fmt.Sprint(taint), func(t *testing.T) {
			body := `request_body_scanning: {enabled: true, action: block, content_entropy_action: block}
flight_recorder: {enabled: true, dir: "` + t.TempDir() + `"}
mcp_input_scanning: {enabled: false, action: block}
mcp_tool_scanning: {enabled: false, action: block}
mcp_tool_policy: {enabled: false, action: block}
mcp_session_binding: {enabled: false}
` + fmt.Sprintf("taint: {enabled: %t}\nsession_profiling: {enabled: true}\n", taint)
			file := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			cmd := DoctorCmd()
			cmd.SetOut(&out)
			cmd.SetArgs([]string{"--config", file, "--json"})
			if err := cmd.Execute(); err != nil {
				t.Errorf("base-clean doctor exit: %v", err)
			}
			var report doctorReport
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Summary.Warnings != 0 || report.Summary.Failures != 0 {
				t.Errorf("unclearable diagnostics: %+v", report.Summary)
			}
		})
	}
}

// This baseline deliberately keeps Defaults untouched: taint is enabled and
// profiling is disabled. Only the three pre-existing warnings affect exit.
func TestDoctorMCPTaintDiagnostics_DefaultsRetainBaseWarningsAndExit(t *testing.T) {
	cfg := config.Defaults()
	if !cfg.Taint.Enabled || cfg.SessionProfiling.Enabled {
		t.Fatal("test requires unchanged taint/profiling defaults")
	}
	var out bytes.Buffer
	cmd := DoctorCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("default doctor unexpectedly succeeded; want base exit 1")
	}
	if got := cliutil.ExitCodeOf(err); got != 1 {
		t.Errorf("default doctor exit=%d want base exit 1", got)
	}
	var commandReport doctorReport
	if err := json.Unmarshal(out.Bytes(), &commandReport); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		report doctorReport
	}{
		{"Defaults", buildDoctorReport(cfg, configLabelDefaults)}, {"command", commandReport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var warnings []string
			for _, c := range tc.report.Checks {
				if c.Status == doctorStatusWarn {
					warnings = append(warnings, c.Name)
				}
			}
			slices.Sort(warnings)
			want := []string{"flight_recorder", "mcp_wrapper_scanning", "request_body_scanning"}
			if !slices.Equal(warnings, want) || tc.report.Summary.Warnings != len(want) || tc.report.Summary.Failures != 0 {
				t.Errorf("default warnings=%v summary=%+v; want base warnings=%v and no failures", warnings, tc.report.Summary, want)
			}
		})
	}
}

func TestDoctorMCPTaintDiagnostics_RecorderNamesHTTPAndMCP(t *testing.T) {
	for _, c := range buildDoctorReport(config.Defaults(), configLabelDefaults).Checks {
		if c.Name != "taint.mcp_recorder" {
			continue
		}
		if c.Status != doctorStatusInfo || c.Surface != doctorSurfaceConfig {
			t.Errorf("cross-surface recorder prerequisite=%+v", c)
		}
		for _, want := range []string{"session_profiling.enabled=false", "MCP stdio/HTTP/WS bridges", "MCP listener", "HTTP proxy", "enable session_profiling and restart"} {
			if !strings.Contains(c.Detail, want) {
				t.Errorf("recorder detail omitted %q: %s", want, c.Detail)
			}
		}
		return
	}
	t.Fatal("recorder prerequisite missing")
}
