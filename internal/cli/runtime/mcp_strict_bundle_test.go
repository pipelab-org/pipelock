// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMCPProxyCmd_StrictBundleIntegrityFailsClosed proves `pipelock mcp proxy`
// refuses to start in strict mode when an installed rule bundle fails integrity
// verification, matching the main proxy server's startup behavior. Without the
// fail-closed check the proxy would silently boot on core patterns only. The
// refusal returns before any upstream dial, so the closed upstream port never
// matters.
func TestMCPProxyCmd_StrictBundleIntegrityFailsClosed(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	bundleDir := filepath.Join(rulesDir, "pipelock-standard")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// bundle.yaml present but bundle.lock absent => integrity-class load error.
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), []byte("name: pipelock-standard\nversion: 2026.01.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "pipelock.yaml")
	cfgYAML := "mode: strict\napi_allowlist:\n  - api.vendor.example\nrules:\n  rules_dir: " + rulesDir + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	// The strict integrity refusal fires in the shared runtime path after
	// config resolve but before any upstream dial or subprocess spawn, so every
	// transport mode must fail closed identically. Prove it on each rather than
	// claim parity: HTTP/WebSocket upstream and stdio subprocess. The closed
	// port / never-run command never matters because the refusal returns first.
	transports := []struct {
		name string
		args []string
	}{
		{name: "http upstream", args: []string{"--upstream", "http://127.0.0.1:1/mcp"}},
		{name: "websocket upstream", args: []string{"--upstream", "ws://127.0.0.1:1/mcp"}},
		{name: "stdio subprocess", args: []string{"--", "cat"}},
	}
	for _, tc := range transports {
		t.Run(tc.name, func(t *testing.T) {
			cmd := mcpProxyCmd()
			cmd.SilenceUsage = true
			cmd.SetArgs(append([]string{"--config", cfgPath}, tc.args...))
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)

			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "rule bundle integrity failure in strict mode") {
				t.Fatalf("strict mcp proxy with integrity-failed bundle: err = %v, want integrity refusal\noutput:\n%s", err, out.String())
			}
		})
	}
}

// TestMCPScanCmd_StrictBundleIntegrity exercises the one-shot consumer, including
// real availability errors and the explicitly opted-in degraded mode.
func TestMCPScanCmd_StrictBundleIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        string
		override    string
		unavailable bool
		wantErr     bool
	}{
		{name: "strict omitted", mode: "strict", wantErr: true},
		{name: "strict blank", mode: "strict", override: "  allow_degraded:\n", wantErr: true},
		{name: "strict null", mode: "strict", override: "  allow_degraded: null\n", wantErr: true},
		{name: "strict false", mode: "strict", override: "  allow_degraded: false\n", wantErr: true},
		{name: "strict override", mode: "strict", override: "  allow_degraded: true\n"},
		{name: "balanced", mode: "balanced"},
		{name: "strict availability", mode: "strict", unavailable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rulesDir := filepath.Join(dir, "rules")
			if tc.unavailable {
				if err := os.WriteFile(rulesDir, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				bundleDir := filepath.Join(rulesDir, "pipelock-standard")
				if err := os.MkdirAll(bundleDir, 0o750); err != nil {
					t.Fatal(err)
				}
				// An installed bundle without its lock is an integrity failure.
				if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), []byte("name: pipelock-standard\nversion: 2026.01.1\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfgPath := filepath.Join(dir, "pipelock.yaml")
			cfgYAML := "mode: " + tc.mode + "\napi_allowlist:\n  - api.vendor.example\nrules:\n  rules_dir: " + rulesDir + "\n" + tc.override
			if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := mcpScanCmd()
			cmd.SilenceUsage = true
			cmd.SetArgs([]string{"--config", cfgPath})
			cmd.SetIn(strings.NewReader(""))
			var out, stderr bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&stderr)
			err := cmd.Execute()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "rule bundle integrity failure in strict mode") {
					t.Fatalf("err = %v, want strict integrity refusal", err)
				}
			} else if err != nil {
				t.Fatalf("advisory bundle failure: %v", err)
			}
			if !strings.Contains(stderr.String(), "warning: bundle") {
				t.Fatalf("missing bundle warning: %s", stderr.String())
			}
		})
	}
}
