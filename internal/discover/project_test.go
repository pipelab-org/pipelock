// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeProjectConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverProjectCommandOrigins(t *testing.T) {
	for _, tc := range []struct {
		name, client, base, parent, child, origin, command, url string
	}{
		{name: "enabled inherits user command", client: clientCodex, base: "command='node'", child: "enabled=true", origin: "user", command: testCmdNode},
		{name: "enabled inherits project command", client: clientCodex, base: "command='base'", parent: "command='node'", child: "enabled=true", origin: "parent", command: testCmdNode},
		{name: "args inherit project command", client: clientCodex, base: "command='base'", parent: "command='node'", child: "args=['server.js']", origin: "parent", command: testCmdNode},
		{name: "nearest command wins", client: clientCodex, base: "command='base'", parent: "command='outer'", child: "command='node'", origin: "child", command: testCmdNode},
		{name: "enabled inherits user URL", client: clientCodex, base: "url='https://api.vendor.example/mcp'", child: "enabled=true", origin: "user", url: "https://api.vendor.example/mcp"},
		{name: "enabled inherits project URL", client: clientCodex, parent: "url='https://api.vendor.example/mcp'", child: "enabled=true", origin: "parent", url: "https://api.vendor.example/mcp"},
		{name: "URL does not shadow inherited command", client: clientCodex, base: "command='node'", child: "url='https://api.vendor.example/mcp'", origin: "user", command: testCmdNode, url: "https://api.vendor.example/mcp"},
		{name: "empty command exposes inherited URL", client: clientCodex, base: "url='https://api.vendor.example/mcp'", parent: "command='outer'", child: "command=''", origin: "user", url: "https://api.vendor.example/mcp"},
		{name: "Grok replaces entire entry", client: clientGrok, base: "command='base'", parent: "command='outer'", child: "command='node'", origin: "child", command: testCmdNode},
		{name: "Grok enabled does not inherit command", client: clientGrok, base: "command='base'", parent: "command='outer'", child: "enabled=true", origin: "child"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, project := t.TempDir(), t.TempDir()
			nested := filepath.Join(project, "nested")
			if err := os.Mkdir(filepath.Join(project, ".git"), 0o750); err != nil {
				t.Fatal(err)
			}
			paths := map[string]string{
				"user":   filepath.Join(home, "."+tc.client, codexConfigName),
				"parent": filepath.Join(project, "."+tc.client, codexConfigName),
				"child":  filepath.Join(nested, "."+tc.client, codexConfigName),
			}
			base := fmt.Sprintf("[projects.%q]\ntrust_level='trusted'\n", project)
			if tc.base != "" {
				base += "[mcp_servers.probe]\n" + tc.base + "\n"
			}
			writeProjectConfig(t, paths["user"], base)
			if tc.parent != "" {
				writeProjectConfig(t, paths["parent"], "[mcp_servers.probe]\n"+tc.parent+"\n")
			}
			writeProjectConfig(t, paths["child"], "[mcp_servers.probe]\n"+tc.child+"\n")
			report, err := DiscoverWithOptions(home, Options{ProjectDirs: []string{nested}})
			if err != nil {
				t.Fatal(err)
			}
			if report.Summary.ParseErrors != 0 {
				t.Fatalf("unexpected parse errors: %+v", report.Clients)
			}
			found := false
			for _, server := range report.Servers {
				if server.Client != tc.client || server.ProjectPath != nested {
					continue
				}
				found = true
				if server.ConfigPath != paths[tc.origin] || server.Command != tc.command || server.URL != tc.url {
					t.Errorf("server = %+v, want config %s, command %q, URL %q", server, paths[tc.origin], tc.command, tc.url)
				}
			}
			if !found {
				t.Fatal("no nested project server discovered")
			}
		})
	}
}

// Trusted/untrusted semantics: https://developers.openai.com/codex/config-basic/
// Field inheritance also reproduced with codex-cli 0.162.0 via
// CODEX_HOME=<fixture> codex mcp list --json in a registered trusted project:
// command changed to upper; args=[inherited] retained; enabled changed to true.
// Grok replacement: https://docs.x.ai/build/features/mcp-servers#project-scope
func TestDiscoverProjectLayers(t *testing.T) {
	for _, tc := range []struct {
		name, client, trust, layer, command, childTrust string
		wantProjects, wantErrors                        int
		wantArgs, noGlobal, missing, nested             bool
	}{
		{name: "trusted command override", client: clientCodex, trust: "trusted", layer: "command='node'\nenabled=true", command: testCmdNode, wantProjects: 1, wantArgs: true},
		{name: "untrusted ignored", client: clientCodex, trust: "untrusted", layer: "command='node'"},
		{name: "unknown trust ignored", client: clientCodex, layer: "command='node'"},
		{name: "malformed trusted file", client: clientCodex, trust: "trusted", layer: "command=[", wantErrors: 1},
		{name: "malformed untrusted ignored", client: clientCodex, trust: "untrusted", layer: "command=["},
		{name: "missing registered trusted directory skipped", client: clientCodex, trust: "trusted", missing: true},
		{name: "missing requested directory (Codex and Grok views)", client: clientCodex, trust: "untrusted", missing: true, wantErrors: 2},
		{name: "enabled inherits wrapper", client: clientCodex, trust: "trusted", layer: "enabled=true", command: "self", wantProjects: 1, wantArgs: true},
		{name: "wrong type rejected", client: clientCodex, trust: "trusted", layer: "args=42", wantErrors: 1},
		{name: "Grok replacement drops args", client: clientGrok, layer: "command='node'", command: testCmdNode, wantProjects: 1},
		{name: "Grok project only", client: clientGrok, layer: "command='node'", command: testCmdNode, wantProjects: 1, noGlobal: true},
		{name: "Grok malformed", client: clientGrok, layer: "command=[", wantErrors: 1},
		{name: "Grok nearest wins", client: clientGrok, layer: "command='node'", command: testCmdNode, wantProjects: 1, nested: true},
		{name: "Codex nearest wins", client: clientCodex, trust: "trusted", layer: "command='node'\nenabled=true", command: testCmdNode, wantProjects: 1, wantArgs: true, nested: true},
		{name: "Codex untrusted child skips only child layer", client: clientCodex, trust: "trusted", childTrust: "untrusted", layer: "command='node'", command: "outer", wantProjects: 1, wantArgs: true, nested: true},
		{name: "Codex trusted child over untrusted root", client: clientCodex, trust: "untrusted", childTrust: "trusted", layer: "command='node'\nenabled=true", command: testCmdNode, wantProjects: 1, wantArgs: true, nested: true},
		{name: "Codex malformed untrusted child ignored", client: clientCodex, trust: "trusted", childTrust: "untrusted", layer: "command=[", command: "outer", wantProjects: 1, wantArgs: true, nested: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, project := t.TempDir(), filepath.Join(t.TempDir(), "project")
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			base := fmt.Sprintf("[mcp_servers.probe]\ncommand=%q\nargs=['mcp','proxy','--','child']\nenabled=false\n", self)
			if tc.trust != "" {
				base += fmt.Sprintf("[projects.%q]\ntrust_level=%q\n", project, tc.trust)
			}
			if !tc.noGlobal {
				writeProjectConfig(t, filepath.Join(home, "."+tc.client, codexConfigName), base)
			}
			cwd := project
			if tc.nested {
				if err := os.MkdirAll(filepath.Join(project, ".git"), 0o750); err != nil {
					t.Fatal(err)
				}
				writeProjectConfig(t, filepath.Join(project, "."+tc.client, codexConfigName), "[mcp_servers.probe]\ncommand='outer'\nenabled=true\n")
				cwd = filepath.Join(project, "nested")
			}
			if tc.childTrust != "" {
				base += fmt.Sprintf("[projects.%q]\ntrust_level=%q\n", cwd, tc.childTrust)
				writeProjectConfig(t, filepath.Join(home, "."+tc.client, codexConfigName), base)
			}
			if !tc.missing {
				writeProjectConfig(t, filepath.Join(cwd, "."+tc.client, codexConfigName), "[mcp_servers.probe]\n"+tc.layer+"\n")
			}
			opts := Options{}
			// Registered Codex projects are discovered without --project. A nested
			// working directory is explicit; its registered parent supplies trust.
			if tc.client == clientGrok || tc.trust != "trusted" || tc.nested {
				opts.ProjectDirs = []string{cwd}
			}
			report, err := DiscoverWithOptions(home, opts)
			if err != nil {
				t.Fatal(err)
			}
			if report.Summary.ParseErrors != tc.wantErrors {
				t.Fatalf("parse errors=%d, want %d: %+v", report.Summary.ParseErrors, tc.wantErrors, report.Clients)
			}
			count := 0
			for _, s := range report.Servers {
				if s.Protection == ProtectedPipelock || s.Protection == ProtectedOther {
					t.Fatalf("unverified launch marked protected: %+v", s)
				}
				if s.ProjectPath != cwd {
					continue
				}
				count++
				command := tc.command
				if command == "self" {
					command = self
				}
				if s.Command != command {
					t.Errorf("command=%q, want %q", s.Command, command)
				}
				if (len(s.Args) > 0) != tc.wantArgs {
					t.Errorf("args=%v, want inherited=%t", s.Args, tc.wantArgs)
				}
				if s.Disabled {
					t.Error("project enabled state not applied")
				}
				if command == self {
					if s.Protection != Unconfirmed {
						t.Errorf("wrapped project state=%s", s.Protection)
					}
				} else if s.Protection != Unprotected {
					t.Errorf("override state=%s", s.Protection)
				}
			}
			if count != tc.wantProjects {
				t.Fatalf("project views=%d, want %d: %+v", count, tc.wantProjects, report.Servers)
			}
			if !tc.noGlobal && tc.client == clientCodex && report.Summary.Disabled < 1 {
				t.Errorf("disabled base not retained: %+v", report.Summary)
			}
		})
	}
}

func TestDiscoverEveryClientWrapperUnconfirmed(t *testing.T) {
	for _, cp := range configPaths(t.TempDir()) {
		t.Run(cp.Client+cp.Path, func(t *testing.T) {
			home := t.TempDir()
			var target clientPath
			for _, candidate := range configPaths(home) {
				if candidate.Client == cp.Client && filepath.Ext(candidate.Path) == filepath.Ext(cp.Path) {
					target = candidate
					break
				}
			}
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			content := fmt.Sprintf(`{"%s":{"probe":{"command":%q,"args":["mcp","proxy","--","child"]}}}`, target.Key, self)
			if target.Client == clientCodex || target.Client == clientGrok {
				content = fmt.Sprintf("[mcp_servers.probe]\ncommand=%q\nargs=['mcp','proxy','--','child']\n", self)
			}
			if filepath.Ext(target.Path) == ".yaml" {
				content = fmt.Sprintf("mcpServers:\n  - name: probe\n    command: %q\n    args: [mcp, proxy, --, child]\n", self)
			}
			writeProjectConfig(t, target.Path, content)
			report, err := Discover(home)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Servers) != 1 || report.Summary.Unconfirmed != 1 || report.Summary.ProtectedPipelock != 0 {
				t.Fatalf("report=%+v servers=%+v", report.Summary, report.Servers)
			}
			server := report.Servers[0]
			if server.Protection != Unconfirmed || !strings.Contains(server.Evidence, "whether the client actually launches it is unconfirmed") || len(server.ParseWarnings) == 0 {
				t.Fatalf("server=%+v", server)
			}
			if got := GenerateWrapper(server); !strings.Contains(got, "another wrapper cannot confirm") {
				t.Errorf("suggestion=%s", got)
			}
			data, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			var output struct {
				Servers []struct {
					State string `json:"protection_state"`
				}
				Summary struct {
					Unconfirmed int `json:"unconfirmed"`
				}
			}
			if err := json.Unmarshal(data, &output); err != nil {
				t.Fatal(err)
			}
			if output.Summary.Unconfirmed != 1 || output.Servers[0].State != "unconfirmed" {
				t.Fatalf("JSON=%s", data)
			}
		})
	}
}

func TestProjectReadFailuresAndEmptyLayers(t *testing.T) {
	for _, mode := range []string{"directory", "symlink loop", "unreadable", "empty", "relative", "missing config", "new server"} {
		t.Run(mode, func(t *testing.T) {
			home, project := t.TempDir(), t.TempDir()
			base := filepath.Join(home, ".grok", codexConfigName)
			writeProjectConfig(t, base, "[mcp_servers.probe]\ncommand='node'\n")
			path := filepath.Join(project, ".grok", codexConfigName)
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			wantErrors := 1
			switch mode {
			case "directory":
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatal(err)
				}
			case "symlink loop":
				if err := os.Symlink(path, path); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			case "unreadable":
				if os.Geteuid() == 0 {
					t.Skip("root can read mode-000 files")
				}
				writeProjectConfig(t, path, "[mcp_servers.probe]\ncommand='node'\n")
				if err := os.Chmod(path, 0); err != nil {
					t.Fatal(err)
				}
				if _, err := os.ReadFile(filepath.Clean(path)); err == nil {
					t.Skip("filesystem does not enforce unreadable file modes")
				}
			case "empty":
				writeProjectConfig(t, path, "[plugins]\nenabled=[]\n")
				wantErrors = 0
			case "relative":
				project = "relative-project"
			case "missing config":
				wantErrors = 0
			case "new server":
				writeProjectConfig(t, path, "[mcp_servers.other]\ncommand='node'\n")
				wantErrors = 0
			}
			report, err := DiscoverWithOptions(home, Options{ProjectDirs: []string{project, project}})
			if err != nil {
				t.Fatal(err)
			}
			// An invalid requested directory is reported for both TOML clients;
			// applicable Grok file failures are counted once after root deduplication.
			if mode == "relative" {
				wantErrors = 2
			}
			if report.Summary.ParseErrors != wantErrors {
				t.Fatalf("parse errors=%d, want %d: %+v", report.Summary.ParseErrors, wantErrors, report.Clients)
			}
		})
	}
}

// A failed layer must not leave a partial project view behind: the view would
// describe a merge the client never performs (it refuses to load the file).
func TestDiscoverProjectParseErrorSuppressesPartialView(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(project, "nested")
	writeProjectConfig(t, filepath.Join(home, ".codex", codexConfigName),
		fmt.Sprintf("[mcp_servers.probe]\ncommand='node'\n[projects.%q]\ntrust_level='trusted'\n", project))
	writeProjectConfig(t, filepath.Join(project, ".codex", codexConfigName), "[mcp_servers.probe]\ncommand='outer'\n")
	malformed := filepath.Join(nested, ".codex", codexConfigName)
	writeProjectConfig(t, malformed, "[mcp_servers.probe]\ncommand=[\n")

	report, err := DiscoverWithOptions(home, Options{ProjectDirs: []string{nested}})
	if err != nil {
		t.Fatal(err)
	}
	failed := false
	for _, c := range report.Clients {
		failed = failed || (c.ConfigPath == malformed && c.ParseError != "")
	}
	if !failed {
		t.Fatalf("malformed nested layer not reported: %+v", report.Clients)
	}
	for _, s := range report.Servers {
		if s.ProjectPath == nested {
			t.Fatalf("partial view emitted for the failed project: %+v", s)
		}
	}
}
