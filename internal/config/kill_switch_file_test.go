// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKillSwitchTokenFileLoadReload(t *testing.T) {
	t.Setenv(EnvKillSwitchAPIToken, "")
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin-token")
	write := func(value string) {
		t.Helper()
		if err := os.WriteFile(tokenPath, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("first-token\n")
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("kill_switch:\n  api_token_file: admin-token\n  api_listen: 127.0.0.1:9091\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := LoadForRuntime(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if first.EffectiveKillSwitchAPIToken() != "first-token" {
		t.Fatal("file token not resolved")
	}
	write("second-token\n")
	resolved, _ := first.ResolveRuntime(RuntimeResolveOpts{})
	if resolved.EffectiveKillSwitchAPIToken() != "first-token" {
		t.Fatal("runtime clone resampled file")
	}
	second, _, err := LoadReload(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if second.EffectiveKillSwitchAPIToken() != "second-token" || first.EffectiveKillSwitchAPIToken() != "first-token" {
		t.Fatal("reload did not isolate credential snapshots")
	}
	write("")
	if _, _, err := LoadReload(cfgPath); err == nil {
		t.Fatal("empty credential accepted")
	}
	if second.EffectiveKillSwitchAPIToken() != "second-token" {
		t.Fatal("failed reload mutated accepted token")
	}
}

func TestKillSwitchTokenFileInputs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	for _, tt := range []struct {
		name, value, path, inline, env string
		wantErr                        bool
	}{
		{name: "crlf", value: "file-token\r\n", path: "$CREDENTIALS_DIRECTORY/admin-token"},
		{name: "credential", value: "file-token\n", path: "$CREDENTIALS_DIRECTORY/admin-token"},
		{name: "env precedence", value: "file-token", path: "$CREDENTIALS_DIRECTORY/admin-token", env: "override-token"},
		{name: "conflicting inline", value: "file-token", path: "$CREDENTIALS_DIRECTORY/admin-token", inline: "inline-token", wantErr: true},
		{name: "empty", path: "$CREDENTIALS_DIRECTORY/admin-token", wantErr: true},
		{name: "empty despite env", path: "$CREDENTIALS_DIRECTORY/admin-token", env: "override-token", wantErr: true},
		{name: "multiline", value: "first\nsecond", path: "$CREDENTIALS_DIRECTORY/admin-token", wantErr: true},
		{name: "space", value: "token with space", path: "$CREDENTIALS_DIRECTORY/admin-token", wantErr: true},
		{name: "nonascii", value: "tökén", path: "$CREDENTIALS_DIRECTORY/admin-token", wantErr: true},
		{name: "nul", value: "first\x00second", path: "$CREDENTIALS_DIRECTORY/admin-token", wantErr: true},
		{name: "missing", path: "$CREDENTIALS_DIRECTORY/absent", wantErr: true},
		{name: "traversal", path: "$CREDENTIALS_DIRECTORY/../admin-token", wantErr: true},
		{name: "directory", path: dir, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvKillSwitchAPIToken, tt.env)
			if err := os.WriteFile(filepath.Join(dir, "admin-token"), []byte(tt.value), 0o600); err != nil {
				t.Fatal(err)
			}
			data := "kill_switch:\n  api_token_file: '" + tt.path + "'\n  api_token: '" + tt.inline + "'\n"
			cfg, err := loadRuntimeTokenBytes([]byte(data))
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error %v", err, tt.wantErr)
			}
			if err != nil {
				if strings.Contains(err.Error(), "first") || strings.Contains(err.Error(), "override-token") {
					t.Fatal("error exposed token")
				}
				return
			}
			want := strings.TrimSuffix(strings.TrimSuffix(tt.value, "\r\n"), "\n")
			if tt.env != "" {
				want = tt.env
			}
			if cfg.EffectiveKillSwitchAPIToken() != want || cfg.KillSwitch.APIToken != "" {
				t.Fatal("incorrect private credential resolution")
			}
		})
	}
}

func TestKillSwitchTokenFileInspectionAndErrors(t *testing.T) {
	t.Setenv(EnvKillSwitchAPIToken, "")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	data := []byte("kill_switch:\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n")
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := LoadForRuntime(cfgPath); err == nil {
		t.Fatal("missing credential directory accepted")
	}
	if _, err := LoadForInspection(cfgPath); err != nil {
		t.Fatal("inspection read runtime credential", err)
	}
	if _, err := LoadPolicyBundleBytes(data); err != nil {
		t.Fatal("policy validation read runtime credential", err)
	}
	path := filepath.Join(dir, "large")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxKillSwitchTokenFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRuntimeTokenBytes([]byte("kill_switch:\n  api_token_file: " + path + "\n")); err == nil {
		t.Fatal("oversized token accepted")
	}
	if _, err := loadRuntimeTokenBytes([]byte("kill_switch:\n  api_token_file: " + dir + "\n")); err == nil {
		t.Fatal("directory accepted")
	}
	for _, name := range []string{"$CREDENTIALS_DIRECTORY", "$CREDENTIALS_DIRECTORY/", "$CREDENTIALS_DIRECTORY/..", "$CREDENTIALS_DIRECTORY/a:b", "$CREDENTIALS_DIRECTORY/" + strings.Repeat("x", 256)} {
		if _, err := KillSwitchCredentialName(name); err == nil {
			t.Fatalf("invalid reference accepted: %q", name)
		}
	}
}

func TestKillSwitchTokenFilePermissions(t *testing.T) {
	t.Setenv(EnvKillSwitchAPIToken, "")
	for _, tt := range []struct {
		name    string
		mode    os.FileMode
		wantErr bool
	}{
		{name: "owner only", mode: 0o600},
		{name: "owner read only", mode: 0o400},
		{name: "group read", mode: 0o640},
		{name: "group write", mode: 0o660, wantErr: true},
		{name: "world read", mode: 0o604, wantErr: true},
		{name: "world readable", mode: 0o644, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "admin-token")
			if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tt.mode); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadRuntimeTokenBytes([]byte("kill_switch:\n  api_token_file: " + path + "\n"))
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error %v", err, tt.wantErr)
			}
			if err == nil && cfg.EffectiveKillSwitchAPIToken() != "file-token" {
				t.Fatal("permitted token file not resolved")
			}
		})
	}
}

func TestKillSwitchTokenFileNullAndBlank(t *testing.T) {
	t.Setenv(EnvKillSwitchAPIToken, "")
	for _, value := range []string{"~", "null", "''", ""} {
		t.Run(value, func(t *testing.T) {
			cfg, err := loadRuntimeTokenBytes([]byte("kill_switch:\n  api_token_file: " + value + "\n"))
			if err != nil {
				t.Fatalf("unset token file rejected: %v", err)
			}
			if cfg.KillSwitch.APITokenFile != "" || cfg.EffectiveKillSwitchAPIToken() != "" {
				t.Fatal("null or blank token file produced a token")
			}
			// Unset must not satisfy the dedicated listener's token requirement.
			if _, err := loadRuntimeTokenBytes([]byte("kill_switch:\n  api_listen: 127.0.0.1:9091\n  api_token_file: " + value + "\n")); err == nil {
				t.Fatal("api_listen accepted a null or blank token file")
			}
		})
	}
}

// Runtime file tests opt in to the same credential path as daemon startup.
func loadRuntimeTokenBytes(data []byte) (*Config, error) {
	return loadBytes(data, "<memory>", ".", loadOptions{resolveLicense: true, resolveRuntimeCredentials: true})
}

func TestKillSwitchTokenFileOperatorLoad(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	for _, env := range []string{"", "operator-token"} {
		t.Run("env="+env, func(t *testing.T) {
			t.Setenv(EnvKillSwitchAPIToken, env)
			path := filepath.Join(t.TempDir(), "config.yaml")
			data := []byte("kill_switch:\n  api_listen: 127.0.0.1:9091\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			for name, load := range map[string]func(string) (*Config, error){"ordinary": Load, "rules": LoadForRules, "inspection": LoadForInspection} {
				t.Run(name, func(t *testing.T) {
					if _, err := load(path); err != nil {
						t.Fatalf("operator load read service credential: %v", err)
					}
				})
			}
			cfg, err := LoadBytes(data)
			if err != nil {
				t.Fatal(err)
			}
			clone, _ := cfg.ResolveRuntime(RuntimeResolveOpts{})
			if err := clone.ResolveRuntimeCredentials(); err == nil {
				t.Fatal("runtime resolution after cloning skipped missing credential")
			}
			if _, err := LoadForRuntime(path); err == nil {
				t.Fatal("startup skipped missing credential")
			}
			if _, hash, err := LoadReload(path); err == nil || hash == "" {
				t.Fatal("reload did not reject missing credential with a source hash")
			}
		})
	}
}

func TestKillSwitchTokenFileOperatorSyntax(t *testing.T) {
	for _, raw := range []string{
		"api_token_file: $CREDENTIALS_DIRECTORY/../admin-token",
		"api_token_file: admin-token\n  api_token: inline-token",
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte("kill_switch:\n  "+raw+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for name, load := range map[string]func(string) (*Config, error){"ordinary": Load, "rules": LoadForRules, "inspection": LoadForInspection, "runtime": LoadForRuntime} {
			t.Run(name+raw, func(t *testing.T) {
				if _, err := load(path); err == nil {
					t.Fatal("invalid token source accepted")
				}
			})
		}
	}
}

func TestKillSwitchTokenFileProgrammaticSource(t *testing.T) {
	cfg := Defaults()
	cfg.KillSwitch.APIToken = "inline-token"
	cfg.KillSwitch.APITokenFile = "admin-token"
	if err := cfg.ResolveRuntimeCredentials(); err == nil {
		t.Fatal("programmatic config accepted conflicting token sources")
	}
}
