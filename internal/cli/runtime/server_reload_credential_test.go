// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
