// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

func TestCodexEnvironmentNeverInArgv(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		name := "add"
		if rollback {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			value := "sk-" + strings.Repeat("synthetic", 5)
			t.Setenv("EXAMPLE_TOKEN", value)
			bin, log := fakeCodex(t, "[]")
			writeShellScript(t, bin, fmt.Sprintf("#!/bin/sh\nprintf '%%s\\000' \"$@\" >> %q\n", log))
			path := filepath.Join(os.Getenv("CODEX_HOME"), "config.toml")
			if err := os.WriteFile(path, []byte("[mcp_servers.example]\ncommand = 'node'\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			original := codexMCPTransport{Type: codexTransportStdio, Command: "node", Env: map[string]string{"EXAMPLE_TOKEN": value}}
			var err error
			if rollback {
				err = rollbackCodexAdd(t.Context(), bin, "example", original)
			} else {
				err = codexReplaceServer(t.Context(), bin, "example", codexMCPTransport{Command: "pipelock", Args: wrapCodexArgs("node", nil, original.Env, ""), Env: original.Env}, original)
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Clean(log))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), value) {
				t.Error("configured value appeared in captured subprocess argv")
			}
			if !strings.Contains(string(data), "mcp\x00add") {
				t.Error("positive control: no add invocation captured")
			}
			if !rollback && !strings.Contains(string(data), "--env\x00EXAMPLE_TOKEN") {
				t.Error("inner wrapper did not forward the name")
			}
			assertCodexEnvNames(t, "example", []string{"EXAMPLE_TOKEN"})
		})
	}
}

// All fixture literals are synthetic. Never consult the developer's Codex home.
func seedCodexTestConfig(t *testing.T, listJSON string) {
	t.Helper()
	t.Setenv("CODEX_HOME", t.TempDir())
	var servers []codexMCPServer
	if err := json.Unmarshal([]byte(listJSON), &servers); err != nil {
		t.Fatal(err)
	}
	entries := make(map[string]any)
	for _, server := range servers {
		entries[server.Name] = map[string]any{"command": server.Transport.Command, "args": server.Transport.Args}
		for key, value := range server.Transport.Env {
			if key != "" && !strings.ContainsAny(key, "=\x00") {
				t.Setenv(key, value)
			}
		}
	}
	var output bytes.Buffer
	if err := toml.NewEncoder(&output).Encode(map[string]any{"mcp_servers": entries}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("CODEX_HOME"), "config.toml"), output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertCodexEnvNames(t *testing.T, name string, want []string) {
	t.Helper()
	path := filepath.Join(os.Getenv("CODEX_HOME"), "config.toml")
	var document struct {
		Servers map[string]struct {
			Env     map[string]string `toml:"env"`
			EnvVars []string          `toml:"env_vars"`
		} `toml:"mcp_servers"`
	}
	if _, err := toml.DecodeFile(path, &document); err != nil {
		t.Fatal(err)
	}
	server, found := document.Servers[name]
	if !found || len(server.Env) != 0 || !reflect.DeepEqual(server.EnvVars, want) {
		t.Fatalf("server %q did not persist exactly the expected environment names", name)
	}
	if runtime.GOOS != osWindows {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("config mode = %o", info.Mode().Perm())
		}
	}
}

func TestCodexEnvironmentRefusalBeforeMutation(t *testing.T) {
	for _, tc := range []struct{ name, inherited string }{
		{"missing", ""}, {"mismatched", "another-value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin, log := fakeCodex(t, "[]")
			const key = "EXAMPLE_TOKEN"
			value := "sk-" + strings.Repeat("synthetic", 5)
			t.Setenv(key, tc.inherited)
			if tc.name == "missing" {
				if err := os.Unsetenv(key); err != nil {
					t.Fatal(err)
				}
			}
			transport := codexMCPTransport{Type: codexTransportStdio, Command: "node", Env: map[string]string{key: value}}
			err := codexReplaceServer(t.Context(), bin, "example", transport, transport)
			if err == nil || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "export") || strings.Contains(err.Error(), value) {
				t.Fatalf("expected refusal naming only key and remedy, got %v", err)
			}
			if data, _ := os.ReadFile(filepath.Clean(log)); len(data) != 0 {
				t.Fatal("refusal spawned a mutating command")
			}
			if err := rollbackCodexAdd(t.Context(), bin, "example", transport); err == nil {
				t.Fatal("rollback accepted unavailable value")
			}
			if data, _ := os.ReadFile(filepath.Clean(log)); len(data) != 0 {
				t.Fatal("rollback refusal spawned a command")
			}
		})
	}
}

func TestCodexEnvironmentMalformedNames(t *testing.T) {
	for _, key := range []string{"", "--config", "A=B", "A\x00B"} {
		t.Run(key, func(t *testing.T) {
			for _, transport := range []codexMCPTransport{
				{Env: map[string]string{key: "test-only-value"}}, {EnvVars: []string{key}},
			} {
				if err := validateCodexEnv(transport); err == nil || !strings.Contains(err.Error(), "name") {
					t.Fatal("malformed name accepted")
				}
				server := codexMCPServer{Transport: transport}
				if unsupportedCodexInstallReason(server) == "" || unsupportedCodexRemoveReason(server) == "" {
					t.Fatal("malformed name reached a plan")
				}
			}
		})
	}
}

func TestCodexEnvironmentWhitelistLifecycle(t *testing.T) {
	bin, log := fakeCodex(t, `[{"name":"example","transport":{"command":"node"}}]`)
	t.Setenv("EXAMPLE_EMPTY", "")
	original := codexMCPTransport{Type: codexTransportStdio, Command: "node", Env: map[string]string{"EXAMPLE_EMPTY": ""}, EnvVars: []string{"EXAMPLE_NAME", "EXAMPLE_EMPTY", "EXAMPLE_NAME"}}
	plans, err := planCodexInstall([]codexMCPServer{{Name: "example", Transport: original}}, pipelockBin, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || plans[0].Action != codexActionWrapStdio {
		t.Fatal("name-only server skipped")
	}
	wrapped := codexMCPTransport{Type: codexTransportStdio, Command: pipelockBin, Args: plans[0].NewArgs, Env: plans[0].Env, EnvVars: plans[0].EnvVars}
	if err := codexReplaceServer(t.Context(), bin, "example", wrapped, original); err != nil {
		t.Fatal(err)
	}
	want := []string{"EXAMPLE_EMPTY", "EXAMPLE_NAME"}
	assertCodexEnvNames(t, "example", want)
	data, err := os.ReadFile(filepath.Clean(log))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "--env EXAMPLE_EMPTY --env EXAMPLE_NAME -- node") {
		t.Fatal("whitelist not passed to inner proxy")
	}
	// Codex now reports only names; remove must retain them too.
	wrapped.Env = nil
	wrapped.EnvVars = want
	removed, err := planCodexRemove([]codexMCPServer{{Name: "example", Transport: wrapped}})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0].Action != codexActionUnwrapStdio {
		t.Fatal("name-only server could not be removed")
	}
	replacement := codexMCPTransport{Type: codexTransportStdio, Command: removed[0].NewCmd, Args: removed[0].NewArgs, EnvVars: removed[0].EnvVars}
	if err := codexReplaceServer(t.Context(), bin, "example", replacement, wrapped); err != nil {
		t.Fatal(err)
	}
	assertCodexEnvNames(t, "example", want)
}

func TestCodexEnvironmentConfigErrors(t *testing.T) {
	for _, tc := range []struct{ name, content, want string }{
		{"malformed", "bad = [sensitive-literal", "cannot parse"},
		{"missing servers", "model = 'example'", "mcp_servers"},
		{"missing server", "[mcp_servers.other]\ncommand = 'node'", "no server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CODEX_HOME", t.TempDir())
			path := filepath.Join(os.Getenv("CODEX_HOME"), "config.toml")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			err := persistCodexEnvNames("example", codexMCPTransport{EnvVars: []string{"EXAMPLE_NAME"}})
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "sensitive-literal") {
				t.Fatalf("unexpected error: %v", err)
			}
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil || string(data) != tc.content {
				t.Fatal("failed update changed the config")
			}
		})
	}
	t.Run("relative home", func(t *testing.T) {
		t.Setenv("CODEX_HOME", "relative")
		if _, err := codexConfigPath(); err == nil {
			t.Fatal("relative home accepted")
		}
	})
	t.Run("default home", func(t *testing.T) {
		t.Setenv("CODEX_HOME", "")
		t.Setenv("HOME", t.TempDir())
		if runtime.GOOS == osWindows {
			t.Setenv("USERPROFILE", t.TempDir())
		}
		path, err := codexConfigPath()
		home, homeErr := os.UserHomeDir()
		if err != nil || homeErr != nil || path != filepath.Join(home, ".codex", "config.toml") {
			t.Fatal("wrong default home")
		}
	})
	t.Run("missing config", func(t *testing.T) {
		t.Setenv("CODEX_HOME", t.TempDir())
		if err := preflightCodexEnv(codexMCPTransport{EnvVars: []string{"EXAMPLE_NAME"}}); err == nil {
			t.Fatal("missing config accepted")
		}
	})
}

func TestCodexEnvironmentPreservesUnrelatedConfig(t *testing.T) {
	t.Setenv("CODEX_HOME", t.TempDir())
	path := filepath.Join(os.Getenv("CODEX_HOME"), "config.toml")
	content := "model = 'example'\n[profiles.work]\nmodel = 'other'\n[mcp_servers.example]\ncommand = 'node'\nargs = ['with spaces']\n[mcp_servers.example.env]\nEXAMPLE_NAME = 'old-value'\n[mcp_servers.other]\nurl = 'https://api.vendor.example/mcp'\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistCodexEnvNames("example", codexMCPTransport{EnvVars: []string{"EXAMPLE_NAME"}}); err != nil {
		t.Fatal(err)
	}
	assertCodexEnvNames(t, "example", []string{"EXAMPLE_NAME"})
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	if _, err := toml.Decode(content, &before); err != nil {
		t.Fatal(err)
	}
	if _, err := toml.Decode(string(data), &after); err != nil {
		t.Fatal(err)
	}
	oldServer := before["mcp_servers"].(map[string]any)["example"].(map[string]any)
	delete(oldServer, "env")
	// Compare the semantic document, allowing only the intended whitelist change.
	delete(after["mcp_servers"].(map[string]any)["example"].(map[string]any), "env_vars")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("unrelated TOML data changed")
	}
}

func TestCodexEnvironmentURLCannotDropWhitelist(t *testing.T) {
	server := codexMCPServer{Name: "example", Transport: codexMCPTransport{
		Type: codexTransportStdio, Command: pipelockBin,
		Args: wrapCodexURL("https://api.vendor.example/mcp", ""), EnvVars: []string{"EXAMPLE_NAME"},
	}}
	if _, err := planCodexRemove([]codexMCPServer{server}); err == nil || !strings.Contains(err.Error(), "environment cannot be preserved") {
		t.Fatalf("URL unwrap silently dropped whitelist: %v", err)
	}
}

func TestCodexEnvironmentConfigFailureRollsBack(t *testing.T) {
	bin, log := fakeCodex(t, `[{"name":"example","transport":{"command":"node"}}]`)
	home := os.Getenv("CODEX_HOME")
	configPath := filepath.Join(home, "config.toml")
	countPath := filepath.Join(home, "add-count")
	// The first add succeeds but produces no matching config entry. Rollback's
	// add restores it, and the shared persistence path must restore the names.
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\000' "$@" >> %q
if [ "$1 $2" = "mcp add" ]; then
 if [ ! -e %q ]; then
  : > %q
  printf 'model = "example"\n' > %q
 else
  printf '[mcp_servers.example]\ncommand = "node"\n' > %q
 fi
fi
`, log, countPath, countPath, configPath, configPath)
	writeShellScript(t, bin, script)
	original := codexMCPTransport{Type: codexTransportStdio, Command: "node", EnvVars: []string{"EXAMPLE_NAME"}}
	err := codexReplaceServer(t.Context(), bin, "example", original, original)
	if err == nil || !strings.Contains(err.Error(), "rolled back to original config") {
		t.Fatalf("wrong rollback outcome: %v", err)
	}
	assertCodexEnvNames(t, "example", []string{"EXAMPLE_NAME"})
	data, readErr := os.ReadFile(filepath.Clean(log))
	if readErr != nil || strings.Count(string(data), "mcp\x00add") != 2 {
		t.Fatal("did not observe both add attempts")
	}
}

func TestCodexEnvironmentPreflightKeepsOriginal(t *testing.T) {
	bin, log := fakeCodex(t, `[{"name":"example","transport":{"command":"node"}}]`)
	t.Setenv("EXAMPLE_TOKEN", "")
	if err := os.Unsetenv("EXAMPLE_TOKEN"); err != nil {
		t.Fatal(err)
	}
	original := codexMCPTransport{Type: codexTransportStdio, Command: "node", Env: map[string]string{"EXAMPLE_TOKEN": "test-only-value"}}
	for _, replaceURL := range []bool{false, true} {
		var err error
		if replaceURL {
			err = codexReplaceURL(t.Context(), bin, "example", "https://api.vendor.example/mcp", original)
		} else {
			err = codexReplaceServer(t.Context(), bin, "example", codexMCPTransport{Command: "node"}, original)
		}
		if err == nil || !strings.Contains(err.Error(), "EXAMPLE_TOKEN") {
			t.Fatal("unrestorable original accepted")
		}
	}
	if data, _ := os.ReadFile(filepath.Clean(log)); len(data) != 0 {
		t.Fatal("preflight removed original server")
	}
}

func TestCodexEnvironmentAtomicWriteFailure(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("Unix directory permissions required")
	}
	home := t.TempDir()
	t.Setenv("CODEX_HOME", home)
	path := filepath.Join(home, "config.toml")
	content := []byte("[mcp_servers.example]\ncommand = 'node'\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, os.ModeDir|0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, os.ModeDir|0o750) })
	err := persistCodexEnvNames("example", codexMCPTransport{EnvVars: []string{"EXAMPLE_NAME"}})
	if err == nil {
		t.Fatal("unwritable config directory accepted")
	}
	data, readErr := os.ReadFile(filepath.Clean(path))
	if readErr != nil || !bytes.Equal(data, content) {
		t.Fatal("failed atomic write damaged original")
	}
}

func TestCodexEnvironmentErrorGuards(t *testing.T) {
	t.Run("invalid persistence name", func(t *testing.T) {
		err := persistCodexEnvNames("example", codexMCPTransport{EnvVars: []string{"A=B"}})
		if err == nil || !strings.Contains(err.Error(), "name") {
			t.Fatal("persistence accepted an invalid name")
		}
	})
	t.Run("relative config path", func(t *testing.T) {
		t.Setenv("CODEX_HOME", "relative")
		if _, _, err := readCodexConfig(); err == nil {
			t.Fatal("read accepted a relative Codex home")
		}
	})
	t.Run("missing home", func(t *testing.T) {
		t.Setenv("CODEX_HOME", "")
		t.Setenv("HOME", "")
		if runtime.GOOS == osWindows {
			t.Setenv("USERPROFILE", "")
		}
		if err := preflightCodexEnv(codexMCPTransport{EnvVars: []string{"EXAMPLE_NAME"}}); err == nil {
			t.Fatal("preflight accepted an unavailable home")
		}
	})
}

const codexLocalTimeChildEnv = "PIPELOCK_TEST_CODEX_LOCAL_TIME_CHILD"

// The TOML library fixes its local-time offset at package init, and Go names the
// local zone differently when TZ=UTC is explicit. Rerun this test in child
// processes for a non-UTC zone and for explicit UTC.
func TestCodexEnvironmentPreservesLocalTimes(t *testing.T) {
	if os.Getenv(codexLocalTimeChildEnv) == "" {
		for _, zone := range []string{"America/New_York", "UTC"} {
			t.Run(zone, func(t *testing.T) {
				if _, err := time.LoadLocation(zone); err != nil {
					t.Skip("zoneinfo unavailable")
				}
				self, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.CommandContext(t.Context(), self, "-test.run=^TestCodexEnvironmentPreservesLocalTimes$", "-test.count=1", "-test.v") // #nosec G204 -- reruns this test binary with a fixed test filter.
				cmd.Env = append(os.Environ(), "TZ="+zone, codexLocalTimeChildEnv+"="+zone)
				out, err := cmd.CombinedOutput()
				if err != nil || !strings.Contains(string(out), "--- PASS: TestCodexEnvironmentPreservesLocalTimes") {
					t.Fatalf("child run failed: %v\n%s", err, out)
				}
			})
		}
		return
	}
	if _, offset := time.Now().Zone(); offset == 0 && os.Getenv(codexLocalTimeChildEnv) != "UTC" {
		t.Fatal("child process did not run with a non-UTC offset")
	}
	t.Setenv("CODEX_HOME", t.TempDir())
	path := filepath.Join(os.Getenv("CODEX_HOME"), "config.toml")
	content := "wake = 07:32:00\nstamp = 2026-01-02T03:04:05\nday = 2026-01-02\nzoned = 2026-01-02T03:04:05+02:00\n" +
		"utc = 2026-01-02T03:04:05Z\nnumeric = 2026-01-02T03:04:05+00:00\nunknown = 2026-01-02T03:04:05-00:00\n" +
		"[mcp_servers.example]\ncommand = 'node'\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistCodexEnvNames("example", codexMCPTransport{EnvVars: []string{"EXAMPLE_NAME"}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	// -00:00 has no distinct decoded form, so it is written as the same zero offset.
	for _, want := range []string{
		"wake = 07:32:00\n", "stamp = 2026-01-02T03:04:05\n", "day = 2026-01-02\n", "zoned = 2026-01-02T03:04:05+02:00\n",
		"utc = 2026-01-02T03:04:05Z\n", "numeric = 2026-01-02T03:04:05+00:00\n", "unknown = 2026-01-02T03:04:05+00:00\n",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("rewrite changed %q:\n%s", strings.TrimSpace(want), data)
		}
	}
}

func TestCodexEnvironmentRefusesLossyRewrite(t *testing.T) {
	// A zone the encoder cannot name reparses as an anonymous offset.
	lossy := map[string]any{"when": time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("example-zone", 3600))}
	if _, err := encodeCodexConfig(lossy); err == nil || !strings.Contains(err.Error(), "without changing other settings") {
		t.Fatalf("lossy rewrite accepted: %v", err)
	}
	faithful := map[string]any{"nan": math.NaN(), "tables": []any{map[string]any{"a": int64(1)}}}
	if _, err := encodeCodexConfig(faithful); err != nil {
		t.Fatalf("faithful rewrite refused: %v", err)
	}
}

func TestCodexEnvironmentWritesThroughSymlink(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("symlink creation needs privileges on Windows")
	}
	t.Setenv("CODEX_HOME", t.TempDir())
	target := filepath.Join(t.TempDir(), "managed.toml")
	if err := os.WriteFile(target, []byte("[mcp_servers.example]\ncommand = 'node'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(os.Getenv("CODEX_HOME"), "config.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := persistCodexEnvNames("example", codexMCPTransport{EnvVars: []string{"EXAMPLE_NAME"}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("config symlink was replaced by a regular file")
	}
	assertCodexEnvNames(t, "example", []string{"EXAMPLE_NAME"})
}
