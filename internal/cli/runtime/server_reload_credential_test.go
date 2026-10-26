// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func TestServerReloadNativeCredential(t *testing.T) {
	t.Setenv(config.EnvKillSwitchAPIToken, "")
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin-token")
	writeToken := func(value string) {
		t.Helper()
		if err := os.WriteFile(tokenPath, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeToken("first-token\n")
	path := writeServerTestConfig(t, "mode: balanced\nkill_switch:\n  api_token_file: "+tokenPath+"\n")
	s, err := NewServer(ServerOpts{ConfigFile: path, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	checkAuth := func(token string, want int) {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/killswitch/status", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.proxy.Handler().ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("admin status=%d want %d", w.Code, want)
		}
	}
	checkAuth("first-token", http.StatusOK)
	s.killswitch.SetAPI(true)
	// First unchanged reload enters dedup; rotation must still apply immediately.
	s.ReloadFile()
	writeToken("second-token\n")
	if out := s.ReloadFile(); out.Verdict != proxy.ReloadAccepted {
		t.Fatalf("rotation: %+v", out)
	}
	checkAuth("first-token", http.StatusUnauthorized)
	checkAuth("second-token", http.StatusOK)
	if !s.killswitch.IsActive() {
		t.Fatal("rotation cleared runtime activation")
	}
	writeToken("")
	if out := s.ReloadFile(); out.Verdict != proxy.ReloadRejected {
		t.Fatalf("empty token reload: %+v", out)
	}
	checkAuth("second-token", http.StatusOK)
	if !s.killswitch.IsActive() {
		t.Fatal("rejected reload cleared runtime activation")
	}
	writeToken("third-token\n")
	if out := s.ReloadFile(); out.Verdict != proxy.ReloadAccepted {
		t.Fatalf("recovery: %+v", out)
	}
	checkAuth("second-token", http.StatusUnauthorized)
	checkAuth("third-token", http.StatusOK)
	if err := os.WriteFile(path, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := s.ReloadFile(); out.Verdict != proxy.ReloadAccepted {
		t.Fatalf("token revocation: %+v", out)
	}
	checkAuth("third-token", http.StatusServiceUnavailable)
	if !s.killswitch.IsActive() {
		t.Fatal("token revocation cleared runtime activation")
	}
	if out := s.ReloadFile(); out.Verdict != proxy.ReloadUnchanged {
		t.Fatalf("unchanged: %+v", out)
	}
}

func TestServerMissingNativeCredential(t *testing.T) {
	t.Setenv(config.EnvKillSwitchAPIToken, "operator-token")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	path := writeServerTestConfig(t, "mode: balanced\nkill_switch:\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n")
	if _, err := NewServer(ServerOpts{ConfigFile: path, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}}); err == nil {
		t.Fatal("server started without its configured credential")
	}
}

func TestServerReloadParsedFileCredential(t *testing.T) {
	t.Setenv(config.EnvKillSwitchAPIToken, "")
	path := writeServerTestConfig(t, "mode: balanced\nkill_switch:\n  api_token: first-token\n")
	s, err := NewServer(ServerOpts{ConfigFile: path, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	if err := os.WriteFile(tokenPath, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("mode: balanced\nkill_switch:\n  api_token_file: "+tokenPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if s.currentConfig().EffectiveKillSwitchAPIToken() != "file-token" {
		t.Fatal("parsed config reload lost its file token")
	}
	if err := os.WriteFile(tokenPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg); err == nil {
		t.Fatal("parsed config reload accepted empty token file")
	}
	if s.currentConfig().EffectiveKillSwitchAPIToken() != "file-token" {
		t.Fatal("rejected parsed config reload replaced accepted token")
	}
}

func TestMCPProxyMissingNativeCredential(t *testing.T) {
	t.Setenv(config.EnvKillSwitchAPIToken, "operator-token")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	path := writeServerTestConfig(t, "kill_switch:\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n")
	cmd := mcpProxyCmd()
	cmd.SetOut(&syncBuffer{})
	cmd.SetErr(&syncBuffer{})
	cmd.SetArgs([]string{"--config", path, "--", "not-launched"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "CREDENTIALS_DIRECTORY") {
		t.Fatalf("MCP proxy did not reject missing credential before launch: %v", err)
	}
}

func TestSandboxMissingNativeCredential(t *testing.T) {
	t.Setenv(config.EnvKillSwitchAPIToken, "operator-token")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	path := writeServerTestConfig(t, "kill_switch:\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n")
	cmd := SandboxCmd()
	cmd.SetOut(&syncBuffer{})
	cmd.SetErr(&syncBuffer{})
	cmd.SetArgs([]string{"--config", path, "--dry-run", "--", "not-launched"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "CREDENTIALS_DIRECTORY") {
		t.Fatalf("sandbox did not reject missing credential before launch: %v", err)
	}
}

func TestGuardMissingNativeCredential(t *testing.T) {
	t.Setenv(config.EnvKillSwitchAPIToken, "operator-token")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	path := writeServerTestConfig(t, "kill_switch:\n  api_token_file: $CREDENTIALS_DIRECTORY/admin-token\n")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := LaunchGuard(GuardLaunchOptions{Config: cfg, Command: []string{"not-launched"}}); err == nil || !strings.Contains(err.Error(), "CREDENTIALS_DIRECTORY") {
		t.Fatalf("Guard did not reject missing credential before launch: %v", err)
	}
}
