// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCodexConfig(t *testing.T, dir, serverName string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, codexConfigName)
	content := "[mcp_servers." + serverName + "]\ncommand = 'node'\nargs = ['server.js']\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAmbientOptionsCodexHome(t *testing.T) {
	env := map[string]string{EnvCodexHome: "/srv/codex-work"}
	got := AmbientOptions(func(k string) string { return env[k] })
	if len(got.CodexHomes) != 1 || got.CodexHomes[0] != "/srv/codex-work" {
		t.Fatalf("AmbientOptions = %+v", got)
	}
	if empty := AmbientOptions(func(string) string { return "" }); len(empty.CodexHomes) != 0 {
		t.Fatalf("unset override produced roots: %+v", empty)
	}
}

// Codex reads and writes <CODEX_HOME>/config.toml in place of
// ~/.codex/config.toml, so a server added through it must be inventoried.
func TestDiscoverWithOptionsCodexHome(t *testing.T) {
	home := t.TempDir()
	defaultPath := writeCodexConfig(t, filepath.Join(home, ".codex"), "default-server")
	altDir := filepath.Join(t.TempDir(), "codex-work")
	altPath := writeCodexConfig(t, altDir, "alt-server")

	report, err := DiscoverWithOptions(home, Options{CodexHomes: []string{altDir}})
	if err != nil {
		t.Fatal(err)
	}
	names := serverNames(report)
	if names["default-server"] != defaultPath || names["alt-server"] != altPath {
		t.Fatalf("servers = %v, want default from %s and alt from %s", names, defaultPath, altPath)
	}
	if report.Summary.TotalClients != 2 || report.Summary.TotalServers != 2 || report.Summary.Unprotected != 2 {
		t.Fatalf("summary = %+v", report.Summary)
	}
}

func TestDiscoverWithOptionsCodexHomeDedupesDefault(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".codex")
	writeCodexConfig(t, dir, "only")

	report, err := DiscoverWithOptions(home, Options{CodexHomes: []string{dir, dir + string(filepath.Separator)}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.TotalClients != 1 || report.Summary.TotalServers != 1 {
		t.Fatalf("the same config reached three ways was counted more than once: %+v", report.Summary)
	}
}

func TestDiscoverWithOptionsRelativeCodexHome(t *testing.T) {
	report, err := DiscoverWithOptions(t.TempDir(), Options{CodexHomes: []string{"relative/codex"}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.ParseErrors != 1 || len(report.Clients) != 1 ||
		report.Clients[0].Client != clientCodex || report.Clients[0].ParseError != errCodexHomeNotAbsolute.Error() {
		t.Fatalf("relative override not reported: %+v %+v", report.Summary, report.Clients)
	}
}

func TestDiscoverWithOptionsMissingCodexHomeFile(t *testing.T) {
	report, err := DiscoverWithOptions(t.TempDir(), Options{CodexHomes: []string{t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.TotalClients != 0 || report.Summary.ParseErrors != 0 {
		t.Fatalf("an absent override file must read as absent: %+v", report.Summary)
	}
}
