// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func executeCodexRepair(t *testing.T, bin, action string) (string, error) {
	t.Helper()
	cmd := newCodexTestRoot()
	args := []string{"codex", action, "--codex-path", bin}
	if action == "install" {
		cfg := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--config", cfg)
	}
	cmd.SetArgs(args)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	err := cmd.ExecuteContext(t.Context())
	return output.String(), err
}

func TestCodexBlockedEnvironmentRefused(t *testing.T) {
	for _, key := range []string{"HTTPS_PROXY", "Http_Proxy", "NODE_OPTIONS", "LD_PRELOAD"} {
		t.Run(key, func(t *testing.T) {
			servers := []codexMCPServer{{Name: "example", Transport: codexMCPTransport{Type: codexTransportStdio, Command: "node", EnvVars: []string{key}}}}
			data, err := json.Marshal(servers)
			if err != nil {
				t.Fatal(err)
			}
			bin, log := fakeCodex(t, string(data))
			path := filepath.Join(os.Getenv("CODEX_HOME"), "config.toml")
			before, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			output, err := executeCodexRepair(t, bin, "install")
			if err == nil || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "blocked") {
				t.Errorf("want explicit blocked-key refusal, got %v; output %s", err, output)
			}
			if strings.Contains(output, "skip example") {
				t.Error("blocked server silently skipped")
			}
			if data, _ := os.ReadFile(filepath.Clean(log)); len(data) != 0 {
				t.Error("blocked environment mutated registration")
			}
			after, readErr := os.ReadFile(filepath.Clean(path))
			if readErr != nil || !bytes.Equal(before, after) {
				t.Error("refusal changed config bytes")
			}
		})
	}
}

func TestCodexSafeEnvironmentInheritedWithoutFlag(t *testing.T) {
	transport := codexMCPTransport{Type: codexTransportStdio, Command: "node", EnvVars: []string{"PATH", "HOME", "EXAMPLE_NAME"}}
	plans, err := planCodexInstall([]codexMCPServer{{Name: "example", Transport: transport}}, pipelockBin, "")
	if err != nil {
		t.Fatal(err)
	}
	args := plans[0].NewArgs
	for i, arg := range args {
		if arg == "--env" && i+1 < len(args) && (args[i+1] == "PATH" || args[i+1] == "HOME") {
			t.Errorf("safe variable emitted as --env: %s", args[i+1])
		}
	}
	data, err := json.Marshal([]codexMCPServer{{Name: "example", Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	bin, _ := fakeCodex(t, string(data))
	output, err := executeCodexRepair(t, bin, "install")
	if err != nil {
		t.Fatal(err)
	}
	assertCodexEnvNames(t, "example", []string{"EXAMPLE_NAME", "HOME", "PATH"})
	if !strings.Contains(output, "Codex must inherit for example: EXAMPLE_NAME, HOME, PATH") {
		t.Errorf("missing runtime-name guidance: %s", output)
	}
}

func TestCodexBatchPreflightBeforeMutation(t *testing.T) {
	for _, action := range []string{"install", "remove"} {
		t.Run(action, func(t *testing.T) {
			servers := []codexMCPServer{
				{Name: "first", Transport: codexMCPTransport{Type: codexTransportStdio, Command: "node", EnvVars: []string{"EXAMPLE_OK"}}},
				{Name: "second", Transport: codexMCPTransport{Type: codexTransportStdio, Command: "node", Env: map[string]string{"EXAMPLE_MISSING": "test-" + "only-value"}}},
			}
			if action == "remove" {
				for i := range servers {
					servers[i].Transport.Command = pipelockBin
					servers[i].Transport.Args = []string{"mcp", "proxy", "--", "node"}
				}
			}
			data, err := json.Marshal(servers)
			if err != nil {
				t.Fatal(err)
			}
			bin, log := fakeCodex(t, string(data))
			if err := os.Unsetenv("EXAMPLE_MISSING"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(os.Getenv("CODEX_HOME"), "config.toml")
			before, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			_, err = executeCodexRepair(t, bin, action)
			if err == nil || !strings.Contains(err.Error(), "EXAMPLE_MISSING") {
				t.Fatalf("want second-server refusal, got %v", err)
			}
			if data, _ := os.ReadFile(filepath.Clean(log)); len(data) != 0 {
				t.Error("earlier server mutated before batch refusal")
			}
			after, readErr := os.ReadFile(filepath.Clean(path))
			if readErr != nil || !bytes.Equal(before, after) {
				t.Error("batch refusal changed config bytes")
			}
		})
	}
}

func TestCodexDiagnosticsWithholdChildOutput(t *testing.T) {
	value := "test-" + "only-parser-value"
	for _, operation := range []string{"list", "add", "remove"} {
		t.Run(operation, func(t *testing.T) {
			bin, _ := fakeCodex(t, `[{"name":"example","transport":{"type":"stdio","command":"node"}}]`)
			list := filepath.Join(filepath.Dir(bin), "list.json")
			script := fmt.Sprintf(`#!/bin/sh
if [ "$2" = %q ]; then
 printf '%%s' %q
 printf '%%s' %q >&2
 exit 7
fi
if [ "$2" = "list" ]; then cat %q; fi
`, operation, value, "env = { API_KEY = \""+value+"\" BROKEN }", list)
			writeShellScript(t, bin, script)
			var data []byte
			var err error
			if operation == "list" {
				data, err = runCodexMCPListCommand(t.Context(), bin)
			} else {
				data, err = runCodexCommand(t.Context(), bin, "mcp", operation, "example")
			}
			if err == nil {
				t.Fatal("expected command failure")
			}
			if strings.Contains(err.Error()+string(data), value) {
				t.Error("child diagnostics exposed environment value")
			}
			if !strings.Contains(err.Error(), "exit status 7") || !strings.Contains(err.Error(), "withheld") {
				t.Errorf("missing safe failure detail: %v", err)
			}
			// Exercise the same failure through operator-facing install/remove.
			action := "install"
			if operation == "remove" {
				action = "remove"
				if err := os.WriteFile(list, []byte(`[{"name":"example","transport":{"type":"stdio","command":"/usr/local/bin/pipelock","args":["mcp","proxy","--","node"]}}]`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			output, err := executeCodexRepair(t, bin, action)
			if err == nil {
				t.Fatal("expected setup failure")
			}
			if strings.Contains(output+err.Error(), value) {
				t.Error("operator output exposed environment value")
			}
		})
	}
}

func TestCodexAlreadyWrappedBlockedEnvironmentRefused(t *testing.T) {
	exe, err := resolvePipelockBinary()
	if err != nil {
		t.Fatal(err)
	}
	_, err = planCodexInstall([]codexMCPServer{{Name: "example", Transport: codexMCPTransport{Type: codexTransportStdio, Command: exe, Args: []string{"mcp", "proxy", "--env", "HTTPS_PROXY", "--", "node"}, EnvVars: []string{"HTTPS_PROXY"}}}}, exe, "")
	if err == nil || !strings.Contains(err.Error(), "HTTPS_PROXY") {
		t.Fatal("already-wrapped blocked server silently skipped")
	}
}

func TestCodexRuntimeEnvironmentGuidance(t *testing.T) {
	for _, action := range []string{"install", "remove"} {
		t.Run(action, func(t *testing.T) {
			value := "test-" + "only-value"
			transport := codexMCPTransport{Type: codexTransportStdio, Command: "node", EnvVars: []string{"EXAMPLE_SECOND"}, Env: map[string]string{"EXAMPLE_FIRST": value}}
			if action == "remove" {
				transport.Command = pipelockBin
				transport.Args = []string{"mcp", "proxy", "--env", "EXAMPLE_FIRST", "--env", "EXAMPLE_SECOND", "--", "node"}
			}
			data, err := json.Marshal([]codexMCPServer{{Name: "example", Transport: transport}})
			if err != nil {
				t.Fatal(err)
			}
			bin, _ := fakeCodex(t, string(data))
			output, err := executeCodexRepair(t, bin, action)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output, "Codex must inherit for example: EXAMPLE_FIRST, EXAMPLE_SECOND") {
				t.Errorf("missing runtime names: %s", output)
			}
			if strings.Contains(output, value) {
				t.Error("runtime guidance exposed an environment value")
			}
		})
	}
}
