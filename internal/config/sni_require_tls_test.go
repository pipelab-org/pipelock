// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestForwardProxySNIRequireTLSValidation(t *testing.T) {
	cfg := Defaults()
	cfg.ForwardProxy.Enabled = true
	verification := false
	requireTLS := true
	cfg.ForwardProxy.SNIVerification = &verification
	cfg.ForwardProxy.SNIRequireTLS = &requireTLS

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "sni_require_tls requires") {
		t.Fatalf("Validate() error = %v, want require-TLS dependency refusal", err)
	}

	requireTLS = false
	cfg.ForwardProxy.SNIRequireTLS = &requireTLS
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit legacy opt-out with SNI verification disabled: %v", err)
	}
}

// Several launchers (sandbox, MCP sandbox bridge, guard, diagnostics) turn the
// forward proxy on after the config has been validated. The dependency check
// must therefore hold whether or not forward_proxy.enabled is set in the file,
// or require-TLS silently never runs once the launcher enables the proxy.
func TestForwardProxySNIRequireTLSValidationWhenForwardProxyDisabled(t *testing.T) {
	boolPtr := func(v bool) *bool { return &v }
	tests := []struct {
		name         string
		verification *bool
		requireTLS   *bool
		wantErr      bool
	}{
		{name: "contradiction refused", verification: boolPtr(false), requireTLS: boolPtr(true), wantErr: true},
		{name: "require with default verification", verification: nil, requireTLS: boolPtr(true), wantErr: false},
		{name: "require with verification", verification: boolPtr(true), requireTLS: boolPtr(true), wantErr: false},
		{name: "verification off without require", verification: boolPtr(false), requireTLS: boolPtr(false), wantErr: false},
		{name: "verification off with require omitted", verification: boolPtr(false), requireTLS: nil, wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.ForwardProxy.Enabled = false
			cfg.ForwardProxy.SNIVerification = tc.verification
			cfg.ForwardProxy.SNIRequireTLS = tc.requireTLS
			err := cfg.Validate()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "sni_require_tls requires") {
					t.Fatalf("Validate() error = %v, want require-TLS dependency refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

// Load is the path both startup and hot reload take, so a file that leaves the
// forward proxy disabled must still be refused with the contradictory pair.
func TestLoadRefusesSNIRequireTLSWithoutVerificationWhenForwardProxyDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := "forward_proxy:\n  enabled: false\n  sni_verification: false\n  sni_require_tls: true\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "sni_require_tls requires") {
		t.Fatalf("Load() error = %v, want require-TLS dependency refusal", err)
	}
}

func TestAuditPresetDoesNotEnforceSNIRequireTLS(t *testing.T) {
	path, err := filepath.Abs("../../configs/audit.yaml")
	if err != nil {
		t.Fatalf("Abs(audit preset): %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(audit preset): %v", err)
	}
	if cfg.EnforceEnabled() {
		t.Fatal("audit preset unexpectedly enables enforcement")
	}
	if cfg.ForwardProxy.SNIRequireTLSEnabled() {
		t.Fatal("audit preset unexpectedly enforces TLS-only CONNECT")
	}
}

func TestForwardProxySNIRequireTLSBooleanLifecycle(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "omitted", body: "forward_proxy: {}\n", want: false},
		{name: "yaml null", body: "forward_proxy:\n  sni_require_tls:\n", want: false},
		{name: "explicit false", body: "forward_proxy:\n  sni_require_tls: false\n", want: false},
		{name: "explicit true", body: "forward_proxy:\n  sni_require_tls: true\n", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			if err := yaml.Unmarshal([]byte(tc.body), &cfg); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if got := cfg.ForwardProxy.SNIRequireTLSEnabled(); got != tc.want {
				t.Fatalf("SNIRequireTLSEnabled() = %t, want %t", got, tc.want)
			}
		})
	}

	var first Config
	if err := yaml.Unmarshal([]byte("forward_proxy:\n  sni_require_tls: false\n"), &first); err != nil {
		t.Fatal(err)
	}
	var unchanged Config
	if err := yaml.Unmarshal([]byte("forward_proxy:\n  sni_require_tls: false\n"), &unchanged); err != nil {
		t.Fatal(err)
	}
	if first.ForwardProxy.SNIRequireTLSEnabled() != unchanged.ForwardProxy.SNIRequireTLSEnabled() {
		t.Fatal("reload without change drifted")
	}
	var changed Config
	if err := yaml.Unmarshal([]byte("forward_proxy:\n  sni_require_tls: true\n"), &changed); err != nil {
		t.Fatal(err)
	}
	if !changed.ForwardProxy.SNIRequireTLSEnabled() {
		t.Fatal("reload with change did not enable sni_require_tls")
	}
}
