// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"os"
	"path/filepath"
	"strings"
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

func TestResolveEndpointServiceCredential(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("kill_switch:\n  api_listen: 127.0.0.1:9091\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, env, flag, url, want string
	}{
		{name: "env with config URL", env: "env-token", want: "env-token"},
		{name: "flag with config URL", flag: "flag-token", want: "flag-token"},
		{name: "flag wins", flag: "flag-token", env: "env-token", want: "flag-token"},
		{name: "explicit endpoint", env: "env-token", url: "http://127.0.0.1:9092", want: "env-token"},
		{name: "no operator credential"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(config.EnvKillSwitchAPIToken, tt.env)
			ep, err := resolveEndpoint(&rootFlags{configPath: path, apiToken: tt.flag, apiURL: tt.url}, defaultResolverDeps())
			if tt.want == "" {
				if err == nil {
					t.Fatal("missing operator credential accepted")
				}
				for _, control := range []string{"--api-token", config.EnvKillSwitchAPIToken, "--api-url"} {
					if !strings.Contains(err.Error(), control) {
						t.Fatalf("error omits usable control %s: %v", control, err)
					}
				}
				return
			}
			wantURL := tt.url
			if wantURL == "" {
				wantURL = "http://127.0.0.1:9091"
			}
			if err != nil || ep.Token != tt.want || ep.URL != wantURL {
				t.Fatalf("endpoint not resolved with operator credential: err=%v", err)
			}
		})
	}
}
