// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func writeClaudeConfig(t *testing.T, dir, serverName string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, claudeGlobalConfigName)
	content := `{"mcpServers":{"` + serverName + `":{"command":"node","args":["server.js"]}}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func serverNames(r *Report) map[string]string {
	names := map[string]string{}
	for _, s := range r.Servers {
		names[s.ServerName] = s.ConfigPath
	}
	return names
}

func TestAmbientOptions(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	env := map[string]string{EnvClaudeConfigDir: "/srv/claude-work"}
	got := AmbientOptions(func(k string) string { return env[k] })
	if len(got.ProjectDirs) != 1 || got.ProjectDirs[0] != cwd {
		t.Fatalf("ambient project directories = %v, want [%s]", got.ProjectDirs, cwd)
	}
	if len(got.ClaudeConfigDirs) != 1 || got.ClaudeConfigDirs[0] != "/srv/claude-work" {
		t.Fatalf("AmbientOptions = %+v", got)
	}
	if empty := AmbientOptions(func(string) string { return "" }); len(empty.ClaudeConfigDirs) != 0 {
		t.Fatalf("unset override produced roots: %+v", empty)
	}
}

// TestDiscoverWithOptionsClaudeConfigDir proves an override root is inventoried
// in addition to the default ~/.claude.json, from <dir>/.claude.json.
func TestDiscoverWithOptionsClaudeConfigDir(t *testing.T) {
	home := t.TempDir()
	defaultPath := writeClaudeConfig(t, home, "default-server")
	altDir := filepath.Join(t.TempDir(), ".claude-work")
	altPath := writeClaudeConfig(t, altDir, "alt-server")

	report, err := DiscoverWithOptions(home, Options{ClaudeConfigDirs: []string{altDir}})
	if err != nil {
		t.Fatal(err)
	}
	names := serverNames(report)
	if names["default-server"] != defaultPath || names["alt-server"] != altPath {
		t.Fatalf("servers = %v, want default from %s and alt from %s", names, defaultPath, altPath)
	}
	if report.Summary.TotalClients != 2 || report.Summary.TotalServers != 2 {
		t.Fatalf("summary = %+v", report.Summary)
	}

	// Without the option the alternate root stays invisible: Discover reads
	// no environment, so its result depends only on its arguments.
	t.Setenv(EnvClaudeConfigDir, altDir)
	plain, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := serverNames(plain)["alt-server"]; ok {
		t.Fatal("Discover read CLAUDE_CONFIG_DIR from the environment")
	}
}

// TestDiscoverWithOptionsDedupesSameFile proves one file reachable from two
// roots (override equal to home, or a symlinked root) is counted once.
func TestDiscoverWithOptionsDedupesSameFile(t *testing.T) {
	home := t.TempDir()
	writeClaudeConfig(t, home, "only-server")
	link := filepath.Join(t.TempDir(), "home-link")
	if err := os.Symlink(home, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	report, err := DiscoverWithOptions(home, Options{ClaudeConfigDirs: []string{home, link}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.TotalServers != 1 || report.Summary.TotalClients != 1 {
		t.Fatalf("same file counted more than once: %+v", report.Summary)
	}
}

// TestDiscoverWithOptionsRelativeClaudeConfigDir proves a relative override is
// reported as a visible error instead of being resolved against an arbitrary
// working directory or silently ignored.
func TestDiscoverWithOptionsRelativeClaudeConfigDir(t *testing.T) {
	home := t.TempDir()
	report, err := DiscoverWithOptions(home, Options{ClaudeConfigDirs: []string{"relative/claude"}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.ParseErrors != 1 {
		t.Fatalf("relative override not reported: %+v", report.Summary)
	}
	if got := report.Clients[0].ParseError; got != errClaudeConfigDirNotAbsolute.Error() {
		t.Fatalf("parse error = %q", got)
	}
}

// TestDiscoverWithOptionsMissingOverrideFile matches the existing convention
// that an absent config file is not a client: Claude Code creates it on first
// use, so there is nothing yet to inventory.
func TestDiscoverWithOptionsMissingOverrideFile(t *testing.T) {
	home := t.TempDir()
	report, err := DiscoverWithOptions(home, Options{ClaudeConfigDirs: []string{filepath.Join(home, "never-used")}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.TotalClients != 0 || report.Summary.ParseErrors != 0 {
		t.Fatalf("summary = %+v", report.Summary)
	}
}

// Shared files can expose different server maps to different clients. Only
// aliases inspected by the same client and parser are duplicate inventories.
func TestDiscoverWithOptionsPreservesClientViews(t *testing.T) {
	for _, tc := range []struct {
		name        string
		content     string
		first       []string
		second      []string
		override    bool
		wantServers int
		wantErrors  int
	}{
		{"different keys", `{"servers":{"vscode-only":{"command":"node"}}}`, []string{".claude.json"}, []string{appDataDir(""), "Code", "User", "mcp.json"}, false, 1, 0},
		{"same keys different clients", `{"mcpServers":{"shared":{"command":"node"}}}`, []string{".claude.json"}, []string{".cursor", "mcp.json"}, false, 2, 0},
		{"Claude project parser", `{"projects":{"/workspace":{"mcpServers":{"project-only":{"command":"node"}}}}}`, []string{".cursor", "mcp.json"}, []string{"override", ".claude.json"}, true, 1, 0},
		{"Continue parser formats", "mcpServers:\n  - name: yaml-only\n    command: node\n", []string{".continue", "config.yaml"}, []string{".continue", "config.json"}, false, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			first := filepath.Join(append([]string{home}, tc.first...)...)
			second := filepath.Join(append([]string{home}, tc.second...)...)
			for _, path := range []string{first, second} {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(first, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(first, second); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			var opts Options
			if tc.override {
				opts.ClaudeConfigDirs = []string{filepath.Dir(second)}
			}
			report, err := DiscoverWithOptions(home, opts)
			if err != nil {
				t.Fatal(err)
			}
			if report.Summary.TotalServers != tc.wantServers || report.Summary.ParseErrors != tc.wantErrors {
				t.Fatalf("summary = %+v, want %d servers and %d errors", report.Summary, tc.wantServers, tc.wantErrors)
			}
		})
	}
}

// TestDiscoverReportsUninspectableConfigPaths proves only proven absence means
// "no config". A config path that exists but cannot be read as a file is a
// visible parse error, never an empty, clean inventory.
func TestDiscoverReportsUninspectableConfigPaths(t *testing.T) {
	t.Run("symlink loop", func(t *testing.T) {
		dir := t.TempDir()
		loop := filepath.Join(dir, claudeGlobalConfigName)
		if err := os.Symlink(loop, loop); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		assertInspectionErrors(t, dir, errConfigUninspectable, 1)
	})
	t.Run("directory in place of file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, claudeGlobalConfigName), 0o750); err != nil {
			t.Fatal(err)
		}
		assertInspectionErrors(t, dir, errConfigNotFile, 1)
	})
	t.Run("permission denied", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses directory permissions")
		}
		parent := t.TempDir()
		dir := filepath.Join(parent, "locked")
		writeClaudeConfig(t, dir, "hidden")
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- cleanup only: TempDir removal needs write and exec back on the directory.
		// A locked directory hides both the current and legacy config
		// names, so neither can be proven absent.
		assertInspectionErrors(t, dir, errConfigUninspectable, 2)
	})
}

func assertInspectionErrors(t *testing.T, claudeDir string, want error, count int) {
	t.Helper()
	report, err := DiscoverWithOptions(t.TempDir(), Options{ClaudeConfigDirs: []string{claudeDir}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.ParseErrors != count || len(report.Clients) != count || report.Summary.TotalServers != 0 {
		t.Fatalf("want %d %q parse errors, got summary %+v clients %+v", count, want, report.Summary, report.Clients)
	}
	for _, c := range report.Clients {
		if c.ParseError != want.Error() {
			t.Fatalf("parse error = %q, want %q", c.ParseError, want)
		}
	}
}

// TestDiscoverInventoriesLegacyClaudeConfig proves the legacy .config.json
// that Claude Code 2.1.0 reads in place of .claude.json is listed, with a
// warning, for both the default ~/.claude dir and a CLAUDE_CONFIG_DIR, and
// never replaces the .claude.json inventory.
func TestDiscoverInventoriesLegacyClaudeConfig(t *testing.T) {
	writeLegacy := func(t *testing.T, dir, name string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		content := `{"mcpServers":{"` + name + `":{"command":"node","args":["s.js"]}}}`
		if err := os.WriteFile(filepath.Join(dir, claudeLegacyConfigName), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	home := t.TempDir()
	writeClaudeConfig(t, home, "current")
	writeLegacy(t, filepath.Join(home, ".claude"), "legacy-default")
	alt := t.TempDir()
	writeLegacy(t, alt, "legacy-override")

	report, err := DiscoverWithOptions(home, Options{ClaudeConfigDirs: []string{alt}})
	if err != nil {
		t.Fatal(err)
	}
	warned := map[string]bool{}
	for _, s := range report.Servers {
		for _, w := range s.ParseWarnings {
			if w == warnClaudeLegacyConfig {
				warned[s.ServerName] = true
			}
		}
	}
	names := serverNames(report)
	if _, ok := names["current"]; !ok || warned["current"] {
		t.Fatalf("current .claude.json server missing or mislabeled: %v warned=%v", names, warned)
	}
	if !warned["legacy-default"] || !warned["legacy-override"] {
		t.Fatalf("legacy servers not inventoried with warning: names=%v warned=%v", names, warned)
	}
}
