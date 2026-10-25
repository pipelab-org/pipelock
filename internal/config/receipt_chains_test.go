// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlightRecorderReceiptChainsLoad(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, value string
		want        int
		invalid     bool
	}{
		{name: "omitted", want: 1},
		{name: "null", value: "null", want: 1},
		{name: "zero", value: "0"},
		{name: "one", value: "1", want: 1},
		{name: "two-inert-without-recorder", value: "2", want: 2},
		{name: "thirty-two-inert-without-recorder", value: "32", want: 32},
		{name: "negative", value: "-1", invalid: true},
		{name: "thirty-three", value: "33", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var body strings.Builder
			body.WriteString("mode: balanced\nflight_recorder:\n  enabled: true\n")
			if tc.value != "" {
				body.WriteString("  receipt_chains: " + tc.value + "\n")
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(body.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if tc.invalid {
				if err == nil || !strings.Contains(err.Error(), "flight_recorder.receipt_chains") {
					t.Fatalf("Load error = %v, want receipt_chains error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.FlightRecorder.ReceiptChainCount(); got != max(tc.want, 1) {
				t.Fatalf("receipt_chains effective = %d, want %d", got, max(tc.want, 1))
			}
		})
	}
}

func TestActiveMultiChainValidation(t *testing.T) {
	cfg := Defaults()
	cfg.FlightRecorder.Dir = t.TempDir()
	cfg.FlightRecorder.ReceiptChains = 2
	cfg.FlightRecorder.SigningKeyPath = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "flight_recorder.receipt_chains") {
		t.Fatalf("multi-chain recorder accepted: %v", err)
	}
	cfg.FlightRecorder.SigningKeyPath = filepath.Join(t.TempDir(), "receipt.key")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("signed multi-chain recorder rejected: %v", err)
	}
	cfg.FlightRecorder.SignCheckpoints = false
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "flight_recorder.sign_checkpoints") {
		t.Fatalf("multi-chain recorder without signed checkpoints accepted: %v", err)
	}
	cfg.FlightRecorder.SignCheckpoints = true
	cfg.FlightRecorder.Anchor.LocalLog = filepath.Join(t.TempDir(), "anchor.log")
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "flight_recorder.receipt_chains") {
		t.Fatalf("multi-chain recorder with anchor accepted: %v", err)
	}
}

func TestReceiptChainsCheckpointSigningLoad(t *testing.T) {
	t.Parallel()
	for _, setup := range []struct {
		name    string
		enabled bool
		dir     string
		chains  int
	}{
		{name: "legacy", enabled: true, dir: "receipts", chains: 0},
		{name: "single", enabled: true, dir: "receipts", chains: 1},
		{name: "multi", enabled: true, dir: "receipts", chains: 2},
		{name: "max-multi", enabled: true, dir: "receipts", chains: 32},
		{name: "disabled", dir: "receipts", chains: 2},
		{name: "empty-dir", enabled: true, chains: 2},
	} {
		for _, signing := range []struct {
			name, field string
			want        bool
		}{
			{name: "omitted", want: true},
			{name: "null", field: "  sign_checkpoints: null\n", want: true},
			{name: "blank", field: "  sign_checkpoints:\n", want: true},
			{name: "false", field: "  sign_checkpoints: false\n"},
			{name: "true", field: "  sign_checkpoints: true\n", want: true},
		} {
			t.Run(setup.name+"/"+signing.name, func(t *testing.T) {
				t.Parallel()
				body := fmt.Sprintf("mode: %s\nflight_recorder:\n  enabled: %t\n  dir: %q\n  receipt_chains: %d\n  signing_key_path: receipt.key\n%s",
					ModeBalanced, setup.enabled, setup.dir, setup.chains, signing.field)
				path := filepath.Join(t.TempDir(), "config.yaml")
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg, err := Load(path)
				invalid := setup.enabled && setup.dir != "" && setup.chains > 1 && !signing.want
				if invalid {
					if err == nil || !strings.Contains(err.Error(), "flight_recorder.sign_checkpoints") {
						t.Fatalf("Load error = %v, want sign_checkpoints error", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if cfg.FlightRecorder.SignCheckpoints != signing.want {
					t.Fatalf("sign_checkpoints = %t, want %t", cfg.FlightRecorder.SignCheckpoints, signing.want)
				}
			})
		}
	}
}

func TestReceiptChainsCheckpointSigningReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	r := NewReloader(path)
	defer r.Close()
	var active *Config
	for _, step := range []struct {
		name, fields string
		invalid      bool
	}{
		{name: "initial-default"},
		{name: "unrelated-reload", fields: "  retention_days: 7\n"},
		{name: "disable-signing", fields: "  sign_checkpoints: false\n", invalid: true},
		{name: "unchanged-invalid", fields: "  sign_checkpoints: false\n", invalid: true},
		{name: "restore-signing", fields: "  sign_checkpoints: true\n"},
		{name: "unchanged-valid", fields: "  sign_checkpoints: true\n"},
	} {
		t.Run(step.name, func(t *testing.T) {
			body := fmt.Sprintf("mode: %s\nflight_recorder:\n  dir: receipts\n  receipt_chains: 2\n  signing_key_path: receipt.key\n%s", ModeBalanced, step.fields)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			r.tryReload(ReloadTriggerFile)
			event := <-r.Reloads()
			if event.SourceHash == "" {
				t.Fatal("reload lost source identity")
			}
			if step.invalid {
				if event.Config != nil || event.Err == nil || !strings.Contains(event.Err.Error(), "flight_recorder.sign_checkpoints") {
					t.Fatalf("reload event = %+v, want sign_checkpoints rejection", event)
				}
				select {
				case <-r.Changes():
					t.Fatal("invalid config replaced active config")
				default:
				}
				if active == nil || !active.FlightRecorder.SignCheckpoints {
					t.Fatal("last accepted signed config was lost")
				}
				return
			}
			if event.Err != nil || event.Config == nil || !event.Config.FlightRecorder.SignCheckpoints {
				t.Fatalf("signed reload rejected: %+v", event)
			}
			active = <-r.Changes()
			if active != event.Config {
				t.Fatal("reload channels disagree on accepted config")
			}
		})
	}
}

func TestReceiptGroupPriorSignerKeysValidation(t *testing.T) {
	valid := strings.Repeat("ab", 32)
	for name, keys := range map[string][]string{
		"valid":     {valid},
		"malformed": {"not-a-key"},
		"uppercase": {strings.ToUpper(valid)},
		"duplicate": {valid, valid},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Defaults()
			cfg.FlightRecorder.ReceiptGroupPriorSignerKeys = keys
			err := cfg.Validate()
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				clone := cfg.Clone()
				clone.FlightRecorder.ReceiptGroupPriorSignerKeys[0] = strings.Repeat("cd", 32)
				if cfg.FlightRecorder.ReceiptGroupPriorSignerKeys[0] != valid {
					t.Fatal("clone shares prior signer key backing slice")
				}
			} else if err == nil || !strings.Contains(err.Error(), "flight_recorder.receipt_group_prior_signer_keys") {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}
