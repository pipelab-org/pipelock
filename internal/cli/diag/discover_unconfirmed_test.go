// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/discover"
)

func TestDiscoverUnconfirmedOutputs(t *testing.T) {
	for _, mode := range []string{"human", "json", "generate"} {
		t.Run(mode, func(t *testing.T) {
			home := t.TempDir()
			if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(protectedDiscoveryConfig(t)), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := DiscoverCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			args := []string{"--home", home}
			if mode != "human" {
				args = append(args, "--"+mode)
			}
			cmd.SetArgs(args)
			var exitErr *cliutil.ExitError
			if err := cmd.Execute(); !errors.As(err, &exitErr) || exitErr.Code != 1 {
				t.Fatalf("error=%v, want exit 1", err)
			}
			if mode == "json" {
				var report discover.Report
				if err := json.Unmarshal(out.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				if report.Summary.Unconfirmed != 1 || report.Summary.ProtectedPipelock != 0 || report.Servers[0].Protection != discover.Unconfirmed {
					t.Fatalf("JSON=%s", out.String())
				}
				return
			}
			if !strings.Contains(out.String(), "Unconfirmed:           1") || !strings.Contains(out.String(), "Wrapper found in this file") || strings.Contains(out.String(), "All servers are protected") {
				t.Fatalf("output=%s", out.String())
			}
			if mode == "generate" && (!strings.Contains(out.String(), "another wrapper suggestion cannot confirm") || strings.Contains(out.String(), "Wrapper suggestions:")) {
				t.Fatalf("generate=%s", out.String())
			}
		})
	}
}

func TestDiscoverProjectFlagAppliesGrokReplacement(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		filepath.Join(home, ".grok", "config.toml"):    "[mcp_servers.probe]\ncommand=" + fmt.Sprintf("%q", self) + "\nargs=['mcp','proxy','--','child']\n",
		filepath.Join(project, ".grok", "config.toml"): "[mcp_servers.probe]\ncommand='node'\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := DiscoverCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--home", home, "--project", project, "--json"})
	var exitErr *cliutil.ExitError
	if err := cmd.Execute(); !errors.As(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("error=%v", err)
	}
	var report discover.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Summary.Unconfirmed != 1 || report.Summary.Unprotected != 1 || report.Summary.ProtectedPipelock != 0 {
		t.Fatalf("summary=%+v", report.Summary)
	}
	for _, server := range report.Servers {
		if server.ProjectPath == project && (server.Command != "node" || len(server.Args) != 0 || server.Protection != discover.Unprotected) {
			t.Fatalf("project server=%+v", server)
		}
	}
}
