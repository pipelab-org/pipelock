// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/spf13/cobra"
)

func TestDoctorWatchOnly(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.WatchOnly = enabled
		cfg.ForwardProxy.Enabled = true
		report := buildDoctorReport(cfg, "test configuration")
		if report.WatchOnly != enabled || doctorGlobalEnforce(cfg) == enabled {
			t.Fatal("doctor disagrees with effective enforcement")
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(encoded), `"watch_only":`) {
			t.Fatal("JSON omits explicit mode")
		}
		found := false
		for _, c := range report.Checks {
			if enabled && strings.Contains(c.Detail, "enforce=false") {
				t.Fatalf("watch-only misreported as audit: %+v", c)
			}
			if c.Name == "watch_only" {
				found = true
				if c.Enforcing || !strings.Contains(c.Detail, "core credential floor") || !strings.Contains(c.Detail, "kill switch") || !strings.Contains(c.Detail, "access controls") {
					t.Fatalf("bad watch-only check: %+v", c)
				}
			}
		}
		if found != enabled {
			t.Fatalf("watch-only check=%t want %t", found, enabled)
		}
		var buf bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&buf)
		printDoctorReport(cmd, report, false)
		if strings.Contains(buf.String(), "Watch-only: enabled") != enabled {
			t.Fatal("text output mode missing or spurious")
		}
	}
}

// watch_only covers plain forward HTTP and fetch. Intercepted HTTPS and the
// Browser Shield on it still apply the configured policy, so doctor must keep
// reporting them as enforcing when enforce is on.
func TestDoctorWatchOnlyKeepsInterceptedHTTPSEnforcement(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	for _, path := range []string{caCert, caKey} {
		if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	enforceOff := false
	for _, tc := range []struct {
		name    string
		enforce *bool
		want    bool
	}{
		{name: "enforce on", want: true},
		{name: "enforce off", enforce: &enforceOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.WatchOnly = true
			cfg.Enforce = tc.enforce
			cfg.TLSInterception = config.TLSInterception{Enabled: true, CACertPath: caCert, CAKeyPath: caKey}
			cfg.BrowserShield.Enabled = true
			if check := checkDoctorTLSInterception(cfg); check.Enforcing != tc.want {
				t.Fatalf("tls_interception = %+v, want enforcing=%v", check, tc.want)
			}
			if check := checkDoctorBrowserShield(cfg); check.Enforcing != tc.want {
				t.Fatalf("browser_shield = %+v, want enforcing=%v", check, tc.want)
			}
		})
	}
}
