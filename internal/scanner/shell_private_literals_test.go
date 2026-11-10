// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestShellPrivateLiterals_CoreFloor pins the shell scanner's allowlist.
// Metadata addresses that sit inside those prefixes pass this floor. The
// shell decision refuses them before the scan; without that refusal the
// allowlisted scan would admit them.
func TestShellPrivateLiterals_CoreFloor(t *testing.T) {
	cfg := config.Defaults()
	cfg.ApplyDefaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = nil
	cfg.DLP.ScanEnv = false

	on, err := NewWithOptions(cfg, Options{ShellPrivateLiterals: true})
	if err != nil {
		t.Fatalf("scanner: %v", err)
	}
	t.Cleanup(on.Close)
	off, err := New(cfg)
	if err != nil {
		t.Fatalf("scanner: %v", err)
	}
	t.Cleanup(off.Close)

	key := "AKIA" + "IOSFODNN7EXAMPLE"
	cases := []struct {
		name    string
		url     string
		allowed bool
		scanner string
	}{
		{name: "loopback", url: "http://127.0.0.1:8080/health", allowed: true},
		{name: "unspecified", url: "http://0.0.0.0:5173", allowed: true},
		{name: "cgnat", url: "http://100.64.0.10/", allowed: true},
		{name: "ula", url: "http://[fd00::1]/", allowed: true},
		{name: "alibaba inside cgnat", url: "http://100.100.100.200/latest/meta-data/", allowed: true},
		{name: "link local", url: "http://169.254.10.10/", allowed: false, scanner: ScannerCoreSSRF},
		{name: "metadata", url: "http://169.254.169.254/latest/meta-data/", allowed: false, scanner: ScannerCoreSSRF},
		{
			name:    "loopback credential",
			url:     "http://127.0.0.1:8080/health?x=" + key,
			allowed: false,
			scanner: ScannerCoreDLP,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := on.Scan(context.Background(), tc.url)
			if got.Allowed != tc.allowed {
				t.Fatalf("allowed = %v, want %v; result = %+v", got.Allowed, tc.allowed, got)
			}
			if tc.scanner != "" && got.Scanner != tc.scanner {
				t.Fatalf("scanner = %s, want %s; reason %q", got.Scanner, tc.scanner, got.Reason)
			}
			if tc.name == "loopback credential" && got.Scanner == ScannerCoreSSRF {
				t.Fatalf("credential URL stopped at core SSRF: %+v", got)
			}
		})
	}
	plain := off.Scan(context.Background(), "http://127.0.0.1:8080/health")
	if plain.Allowed || plain.Scanner != ScannerCoreSSRF {
		t.Fatalf("scanner without the shell allowlist = %+v, want core SSRF", plain)
	}
}
