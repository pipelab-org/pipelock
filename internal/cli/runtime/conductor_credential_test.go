//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// A policy bundle is loaded without runtime file access, so a follower whose
// admin token comes only from kill_switch.api_token_file must keep its
// accepted snapshot across a Conductor apply instead of losing the API.
func TestConductorApplyPreservesFileToken(t *testing.T) {
	t.Setenv(config.EnvKillSwitchAPIToken, "")
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin-token")
	writeToken := func(value string) {
		t.Helper()
		if err := os.WriteFile(tokenPath, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeToken("file-token\n")
	path := writeServerTestConfig(t, "mode: strict\napi_allowlist:\n  - api.vendor.example\nkill_switch:\n  api_token_file: "+tokenPath+"\n")
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
	checkAuth("file-token", http.StatusOK)
	s.killswitch.SetAPI(true)

	raw := "mode: strict\napi_allowlist:\n  - bundle.vendor.example\n"
	candidate, err := config.LoadPolicyBundleBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if candidate.EffectiveKillSwitchAPIToken() != "" {
		t.Fatal("policy bundle must not resolve a follower-local token")
	}
	if err := s.reloadConductorPolicyBundle(candidate, raw); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.currentConfig().APIAllowlist, "bundle.vendor.example") {
		t.Fatal("bundle was not applied")
	}
	checkAuth("file-token", http.StatusOK)
	if !s.killswitch.IsActive() {
		t.Fatal("conductor apply cleared runtime activation")
	}

	// A later operator rotation still replaces the preserved snapshot.
	writeToken("rotated-token\n")
	if out := s.ReloadFile(); out.Verdict != proxy.ReloadAccepted {
		t.Fatalf("rotation after apply: %+v", out)
	}
	checkAuth("file-token", http.StatusUnauthorized)
	checkAuth("rotated-token", http.StatusOK)
}
