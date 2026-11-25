// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCardBareActionDefaultsAndReload(t *testing.T) {
	if Defaults().DLP.CardBareAction != ActionBlock {
		t.Fatal("unsafe default")
	}
	for _, tc := range []struct {
		name, yaml, want string
		invalid          bool
	}{
		{"omitted", "mode: balanced\n", ActionBlock, false},
		{"null", "dlp:\n  card_bare_action: null\n", ActionBlock, false},
		{"blank", "dlp:\n  card_bare_action:\n", ActionBlock, false},
		{"empty", "dlp:\n  card_bare_action: ''\n", ActionBlock, false},
		{"warn", "dlp:\n  card_bare_action: warn\n", ActionWarn, false},
		{"block", "dlp:\n  card_bare_action: block\n", ActionBlock, false},
		{"invalid", "dlp:\n  card_bare_action: allow\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(tc.yaml))
			if tc.invalid {
				if err == nil {
					t.Fatal("accepted invalid action")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.DLP.CardBareAction != tc.want {
				t.Fatalf("got %q", cfg.DLP.CardBareAction)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	r := NewReloader(path)
	defer r.Close()
	for _, action := range []string{ActionBlock, ActionWarn, ActionWarn, ActionBlock, ""} {
		yaml := "dlp:\n  card_bare_action: " + action + "\n"
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		r.tryReload(ReloadTriggerSignal)
		event := <-r.Reloads()
		if event.Config == nil {
			t.Fatalf("reload failed: %+v", event)
		}
		want := action
		if want == "" {
			want = ActionBlock
		}
		if event.Config.DLP.CardBareAction != want {
			t.Fatalf("reload got %q want %q", event.Config.DLP.CardBareAction, want)
		}
	}
}

func TestCardBareActionReloadDowngrade(t *testing.T) {
	old := Defaults()
	updated := Defaults()
	updated.DLP.CardBareAction = ActionWarn
	found := false
	for _, warning := range ValidateReload(old, updated) {
		if warning.Field == "dlp.card_bare_action" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing downgrade warning")
	}
	for _, warning := range ValidateReload(updated, old) {
		if warning.Field == "dlp.card_bare_action" {
			t.Fatal("upgrade marked as downgrade")
		}
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("dlp:\n  card_bare_action: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewReloader(path)
	defer r.Close()
	r.tryReload(ReloadTriggerSignal)
	event := <-r.Reloads()
	if event.Config != nil || event.Err == nil {
		t.Fatalf("invalid reload accepted: %+v", event)
	}
	select {
	case <-r.Changes():
		t.Fatal("invalid config published")
	default:
	}
}

func TestCardBareActionPresets(t *testing.T) {
	for _, name := range []string{"audit", "balanced", "strict", "hostile-model", "claude-code", "cursor", "generic-agent"} {
		cfg, err := Load(filepath.Join("..", "..", "configs", name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DLP.CardBareAction != ActionBlock {
			t.Fatalf("%s changed card default", name)
		}
	}
}
