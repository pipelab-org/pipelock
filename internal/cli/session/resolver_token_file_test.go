// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestResolveEndpointConfigTokenFile(t *testing.T) {
	t.Setenv(config.EnvKillSwitchAPIToken, "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "admin-token"), []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("kill_switch:\n  api_listen: 127.0.0.1:9091\n  api_token_file: admin-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := defaultResolverDeps()
	deps.getenv = func(string) string { return "" }
	ep, err := resolveEndpoint(&rootFlags{configPath: cfgPath}, deps)
	if err != nil {
		t.Fatalf("token file not honored: %v", err)
	}
	if ep.Token != "file-token" {
		t.Fatal("resolved token does not come from api_token_file")
	}
}
