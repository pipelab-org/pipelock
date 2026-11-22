// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"strings"
	"testing"
)

func TestConnectPortsValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ports   []int
		wantErr string
	}{
		{name: "absent"},
		{name: "valid", ports: []int{443, 8443}},
		{name: "zero", ports: []int{0}, wantErr: "between 1 and 65535"},
		{name: "too_large", ports: []int{65536}, wantErr: "between 1 and 65535"},
		{name: "negative", ports: []int{-1}, wantErr: "between 1 and 65535"},
		{name: "duplicate", ports: []int{443, 443}, wantErr: "duplicate port 443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			// Sandbox launchers turn the forward proxy on after validation, so
			// the list is checked even while it is off.
			cfg.ForwardProxy.Enabled = false
			cfg.ForwardProxy.ConnectPorts = tc.ports
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate err=%v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestConnectPortAllowed(t *testing.T) {
	open := ForwardProxy{}
	if !open.ConnectPortAllowed(22) || !open.ConnectPortAllowed(443) {
		t.Fatal("an empty list must admit every port")
	}
	listed := ForwardProxy{ConnectPorts: []int{443, 8443}}
	if !listed.ConnectPortAllowed(443) || !listed.ConnectPortAllowed(8443) || listed.ConnectPortAllowed(22) || listed.ConnectPortAllowed(0) {
		t.Fatal("a non-empty list must admit exactly its ports")
	}
}

func TestConnectPortsCanonicalForm(t *testing.T) {
	hash := func(ports []int) string {
		cfg := Defaults()
		// No ApplyDefaults: the hash itself must treat the list as a set,
		// even for a config that skipped normalization.
		cfg.ForwardProxy.ConnectPorts = ports
		return cfg.computeCanonicalPolicyHash()
	}
	if hash(nil) != hash([]int{}) {
		t.Fatal("absent and empty connect_ports must hash the same")
	}
	if hash([]int{443, 8443}) != hash([]int{8443, 443}) {
		t.Fatal("reordered connect_ports must hash the same")
	}
	if hash([]int{443}) == hash(nil) || hash([]int{443}) == hash([]int{8443}) {
		t.Fatal("connect_ports must change the policy hash")
	}

	cfg := Defaults()
	cfg.ForwardProxy.ConnectPorts = []int{8443, 443}
	cfg.ApplyDefaults()
	if !slices.Equal(cfg.ForwardProxy.ConnectPorts, []int{443, 8443}) {
		t.Fatalf("normalized ports=%v, want sorted", cfg.ForwardProxy.ConnectPorts)
	}
	cfg.ForwardProxy.ConnectPorts = []int{}
	cfg.ApplyDefaults()
	if cfg.ForwardProxy.ConnectPorts != nil {
		t.Fatal("an empty list must normalize to absent")
	}
}

func TestConnectPortsClone(t *testing.T) {
	cfg := Defaults()
	cfg.ForwardProxy.ConnectPorts = []int{443}
	clone := cfg.Clone()
	clone.ForwardProxy.ConnectPorts[0] = 22
	if cfg.ForwardProxy.ConnectPorts[0] != 443 {
		t.Fatal("Clone shares the connect_ports backing array")
	}
}

func TestValidateReloadConnectPorts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		old, new []int
		warn     bool
	}{
		{name: "tighten_from_any", old: nil, new: []int{443}},
		{name: "remove_port", old: []int{443, 8443}, new: []int{443}},
		{name: "reorder", old: []int{443, 8443}, new: []int{8443, 443}},
		{name: "unchanged_any", old: nil, new: nil},
		{name: "add_port", old: []int{443}, new: []int{443, 8443}, warn: true},
		{name: "mixed_add_remove", old: []int{443, 8443}, new: []int{443, 8080}, warn: true},
		{name: "clear", old: []int{443}, new: nil, warn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldCfg, newCfg := Defaults(), Defaults()
			oldCfg.ForwardProxy.ConnectPorts = tc.old
			newCfg.ForwardProxy.ConnectPorts = tc.new
			var got *ReloadWarning
			for _, w := range ValidateReload(oldCfg, newCfg) {
				if w.Field == "forward_proxy.connect_ports" {
					w := w
					got = &w
				}
			}
			if tc.warn != (got != nil) {
				t.Fatalf("warning=%+v, want warning=%v", got, tc.warn)
			}
			// A widening must be able to block a reload under strict mode or
			// a required contract, so it must not be advisory.
			if got != nil && got.Disposition == ReloadWarningDispositionAdvisory {
				t.Fatalf("widening warning is advisory: %+v", got)
			}
		})
	}
}
