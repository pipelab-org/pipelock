// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverWrapperLaunchEvidence(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []string{clientClaudeCode, clientCodex, clientGrok} {
		t.Run(client, func(t *testing.T) {
			home, project := t.TempDir(), t.TempDir()
			if client == clientClaudeCode {
				entry := map[string]any{"command": self, "args": []string{"mcp", "proxy", "--", "node"}}
				content, marshalErr := json.Marshal(map[string]any{
					"mcpServers": map[string]any{"global": entry},
					"projects":   map[string]any{project: map[string]any{"mcpServers": map[string]any{"project": entry}}},
				})
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				writeProjectConfig(t, filepath.Join(home, claudeGlobalConfigName), string(content))
			} else {
				if mkdirErr := os.Mkdir(filepath.Join(project, ".git"), 0o750); mkdirErr != nil {
					t.Fatal(mkdirErr)
				}
				entry := fmt.Sprintf("command=%q\nargs=['mcp','proxy','--','node']\n", self)
				base := fmt.Sprintf("[projects.%q]\ntrust_level='trusted'\n[mcp_servers.global]\n", project) + entry
				writeProjectConfig(t, filepath.Join(home, "."+client, codexConfigName), base)
				writeProjectConfig(t, filepath.Join(project, "."+client, codexConfigName), "[mcp_servers.project]\n"+entry)
			}
			report, discoverErr := DiscoverWithOptions(home, Options{ProjectDirs: []string{project}})
			if discoverErr != nil {
				t.Fatal(discoverErr)
			}
			seenGlobal, seenProject := false, false
			for _, server := range report.Servers {
				if server.Client != client {
					continue
				}
				want := evidenceLaunchUnconfirmed
				if server.ProjectPath != "" {
					seenProject = true
					if client == clientCodex || client == clientGrok {
						want = evidenceProjectLaunchUnconfirmed
					}
				} else {
					seenGlobal = true
				}
				if server.Protection != Unconfirmed || server.Evidence != want {
					t.Errorf("server %s project %q: protection=%s evidence=%q, want unconfirmed %q", server.ServerName, server.ProjectPath, server.Protection, server.Evidence, want)
				}
			}
			if !seenGlobal || !seenProject || report.Summary.ParseErrors != 0 {
				t.Fatalf("missing global/project view or parse errors: %+v", report)
			}
		})
	}
}

func TestDiscoverNonDirectoryConfigParents(t *testing.T) {
	t.Run("missing user parent preserves project config", func(t *testing.T) {
		home, project := t.TempDir(), t.TempDir()
		writeProjectConfig(t, filepath.Join(home, ".grok"), "regular file")
		if err := os.Mkdir(filepath.Join(project, ".git"), 0o750); err != nil {
			t.Fatal(err)
		}
		writeProjectConfig(t, filepath.Join(project, ".grok", codexConfigName), "[mcp_servers.probe]\ncommand='node'\n")
		report, err := DiscoverWithOptions(home, Options{ProjectDirs: []string{project}})
		if err != nil {
			t.Fatal(err)
		}
		if report.Summary.ParseErrors != 0 || report.Summary.TotalServers != 1 || report.Summary.Unprotected != 1 {
			t.Fatalf("readable project config lost or misclassified: %+v", report)
		}
	})
	t.Run("legacy path preserves current config", func(t *testing.T) {
		home := t.TempDir()
		writeClaudeConfig(t, home, "current")
		writeProjectConfig(t, filepath.Join(home, ".claude"), "regular file")
		report, err := Discover(home)
		if err != nil {
			t.Fatal(err)
		}
		if report.Summary.ParseErrors != 0 || report.Summary.TotalServers != 1 || report.Servers[0].Protection != Unprotected {
			t.Fatalf("readable current config lost or misclassified: %+v", report)
		}
	})
	for _, client := range []string{clientCodex, clientGrok} {
		t.Run(client+" preserves readable ancestor layer", func(t *testing.T) {
			home, project := t.TempDir(), t.TempDir()
			nested := filepath.Join(project, "nested")
			if err := os.Mkdir(filepath.Join(project, ".git"), 0o750); err != nil {
				t.Fatal(err)
			}
			base := fmt.Sprintf("[projects.%q]\ntrust_level='trusted'\n[mcp_servers.probe]\ncommand='base'\n", project)
			writeProjectConfig(t, filepath.Join(home, "."+client, codexConfigName), base)
			writeProjectConfig(t, filepath.Join(project, "."+client, codexConfigName), "[mcp_servers.probe]\ncommand='node'\n")
			writeProjectConfig(t, filepath.Join(nested, "."+client), "regular file")
			report, err := DiscoverWithOptions(home, Options{ProjectDirs: []string{nested}})
			if err != nil {
				t.Fatal(err)
			}
			wantServers := 2 // user view and the requested nested project
			if client == clientCodex {
				wantServers++ // registered trusted project also has its own view
			}
			if report.Summary.ParseErrors != 0 || report.Summary.TotalServers != wantServers || report.Summary.Unprotected != wantServers {
				t.Fatalf("unexpected inventory: %+v", report)
			}
			found := false
			for _, server := range report.Servers {
				if server.ProjectPath == nested && server.Command == testCmdNode {
					found = true
				}
			}
			if !found {
				t.Fatal("readable ancestor layer was hidden")
			}
		})
	}
}
