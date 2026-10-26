// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/setup"
)

func TestCodexSetupEnvironmentMatchesChildBuilder(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("shell fixture requires Unix")
	}
	dir := t.TempDir()
	t.Setenv("CODEX_HOME", dir)
	config := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(config, []byte("[mcp_servers.example]\ncommand = 'node'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	argv := filepath.Join(dir, "argv")
	bin := filepath.Join(dir, "codex")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$2" = "list" ]; then
 printf '%%s' '[{"name":"example","transport":{"type":"stdio","command":"node","env_vars":["PATH","HOME","EXAMPLE_NAME"]}}]'
fi
if [ "$2" = "add" ]; then printf '%%s\000' "$@" > %q; fi
`, argv)
	if err := os.WriteFile(bin, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o700); err != nil { // #nosec G302 -- private shell fixture needs the owner-execute bit.
		t.Fatal(err)
	}
	cmd := setup.CodexCmd()
	cmd.SetArgs([]string{"install", "--config", cfg, "--codex-path", bin})
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Clean(argv))
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(string(data), "\x00")
	start := slices.Index(args, "proxy")
	if start < 0 {
		t.Fatal("no generated wrapper invocation captured")
	}
	var envFlags []string
	for i := start + 1; i < len(args) && args[i] != "--"; i++ {
		if args[i] == "--env" && i+1 < len(args) {
			envFlags = append(envFlags, args[i+1])
			i++
		}
	}
	if !slices.Equal(envFlags, []string{"EXAMPLE_NAME"}) {
		t.Fatalf("generated --env entries = %q", envFlags)
	}
	value := "test-" + "only-value"
	extra, err := buildChildExtraEnv(nil, envFlags, fakeLookup(map[string]string{"EXAMPLE_NAME": value}))
	if err != nil {
		t.Fatalf("installer generated arguments rejected by runtime: %v", err)
	}
	if !slices.Equal(extra, []string{"EXAMPLE_NAME=" + value}) {
		t.Fatal("runtime did not forward the explicit environment name")
	}
}
