// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/proxyhealth"
)

func TestStatusCmdLiveIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" || r.URL.RawQuery != "identity=1" || r.Header.Get(edition.AgentHeader) != "test-caller" {
			t.Error("unexpected live probe")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "identity": proxyhealth.Identity{RuntimeSource: "loaded-runtime", Available: true, ActorAuth: envelope.ActorAuthSelfDeclared, DefaultIdentityConfigured: true}})
	}))
	defer srv.Close()
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			args := []string{"--identity-url", srv.URL, "--identity-agent", "test-caller"}
			if format == "json" {
				args = append(args, "--json")
			}
			out, err := runStatusCmd(t, args...)
			if err != nil {
				t.Fatal(err)
			}
			if format == "json" {
				var report statusReport
				if err := json.Unmarshal([]byte(out), &report); err != nil {
					t.Fatal(err)
				}
				if report.ConfigurationSource != "local-configuration" {
					t.Fatal("local configuration provenance missing")
				}
				if report.Identity == nil || report.Identity.ActorAuth != envelope.ActorAuthSelfDeclared || report.Identity.TrustedForIdentity {
					t.Fatalf("wrong live result: %+v", report.Identity)
				}
			} else {
				for _, want := range []string{"Identity (loaded runtime; this request)", "grade=self-declared", "trusted=false", "Local configured state"} {
					if !strings.Contains(out, want) {
						t.Fatalf("output missing %s", want)
					}
				}
			}
			if strings.Contains(out, "test-caller") {
				t.Fatal("caller name echoed")
			}
		})
	}
}

func TestStatusCmdIdentityFailures(t *testing.T) {
	if _, err := runStatusCmd(t, "--identity-agent", "test-caller"); err == nil {
		t.Fatal("header accepted without probe")
	}
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "http://api.vendor.example")
				w.WriteHeader(status)
				_, _ = w.Write([]byte("sensitive-value"))
			}))
			defer srv.Close()
			out, err := runStatusCmd(t, "--identity-url", srv.URL, "--json")
			if err == nil || out != "" || strings.Contains(err.Error(), "sensitive-value") {
				t.Fatalf("invalid probe accepted or leaked: %s %v", out, err)
			}
		})
	}
}
