// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxyhealth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

func validIdentityJSON(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"status": "healthy", "identity": Identity{RuntimeSource: "loaded-runtime", Available: true, ActorAuth: envelope.ActorAuthConfigDefault, TrustedForIdentity: true}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestGetIdentity(t *testing.T) {
	valid := validIdentityJSON(t)
	for _, tt := range []struct {
		name, body string
		status     int
		wantError  bool
	}{
		{"valid", valid, http.StatusOK, false},
		{"missing diagnostic", `{"status":"healthy"}`, http.StatusOK, true},
		{"bad JSON", `secret-sensitive-body`, http.StatusOK, true},
		{"not object", `[]`, http.StatusOK, true},
		{"trailing JSON", valid + `{}`, http.StatusOK, true},
		{"null field", strings.Replace(valid, `"available":true`, `"available":null`, 1), http.StatusOK, true},
		{"missing field", strings.Replace(valid, `"available":true,`, ``, 1), http.StatusOK, true},
		{"bad field", strings.Replace(valid, `"available":true`, `"available":"true"`, 1), http.StatusOK, true},
		{"duplicate field", strings.Replace(valid, `"available":true`, `"available":true,"available":false`, 1), http.StatusOK, true},
		{"unknown grade", strings.Replace(valid, `config-default`, `other-grade`, 1), http.StatusOK, true},
		{"missing source", strings.Replace(valid, `loaded-runtime`, `local-config`, 1), http.StatusOK, true},
		{"unavailable", strings.Replace(valid, `"available":true`, `"available":false`, 1), http.StatusOK, true},
		{"unhealthy", strings.Replace(valid, `healthy`, `unhealthy`, 1), http.StatusOK, true},
		{"trust mismatch", strings.Replace(valid, `config-default`, `self-declared`, 1), http.StatusOK, true},
		{"eligibility mismatch", strings.Replace(valid, `"issuer_id_evidence_eligible":false`, `"issuer_id_evidence_eligible":true`, 1), http.StatusOK, true},
		{"non success", `secret-sensitive-body`, http.StatusForbidden, true},
		{"oversize", strings.Repeat("x", (64<<10)+1), http.StatusOK, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" || r.URL.RawQuery != "identity=1" || r.Header.Get(edition.AgentHeader) != "test-caller" {
					t.Error("unexpected identity request")
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			got, err := GetIdentity(t.Context(), srv.Client(), srv.URL, "test-caller")
			if (err != nil) != tt.wantError {
				t.Fatalf("result = %+v, err=%v", got, err)
			}
			if err != nil && strings.Contains(err.Error(), "secret-sensitive-body") {
				t.Fatal("remote body exposed")
			}
		})
	}
}

func TestGetIdentityRejectsOriginsAndHeaders(t *testing.T) {
	for _, target := range []string{"", "file:///health", "http://user:private@api.vendor.example", "http://api.vendor.example/health", "http://api.vendor.example/?agent=bound", "http://api.vendor.example/#fragment", "%"} {
		t.Run(target, func(t *testing.T) {
			if _, err := GetIdentity(t.Context(), http.DefaultClient, target, ""); err == nil {
				t.Fatal("invalid origin accepted")
			}
		})
	}
	if _, err := GetIdentity(t.Context(), http.DefaultClient, "http://api.vendor.example", "bad\r\nvalue"); err == nil {
		t.Fatal("invalid header accepted")
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	if _, err := GetIdentity(t.Context(), srv.Client(), srv.URL, ""); err == nil || strings.Contains(err.Error(), srv.URL) {
		t.Fatal("network error missing or exposes target")
	}
}
