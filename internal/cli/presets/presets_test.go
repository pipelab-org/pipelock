// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/configs"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestYAMLProducesLoadableConfigForEveryPreset(t *testing.T) {
	t.Parallel()

	for _, name := range All {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := YAML(name)
			if err != nil {
				t.Fatalf("YAML(%q): %v", name, err)
			}

			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatalf("writing config: %v", err)
			}

			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load(%q): %v", name, err)
			}
			if got, want := cfg.Mode, expectedMode(name); got != want {
				t.Fatalf("mode = %q, want %q", got, want)
			}
			parsed, err := Config(name)
			if err != nil {
				t.Fatal(err)
			}
			if !isNamedPreset(name) && cfg.CanonicalPolicyHash() != parsed.CanonicalPolicyHash() {
				t.Fatal("portable preset differs from runtime file loading")
			}
		})
	}
}

func TestConfigAcceptsEveryPreset(t *testing.T) {
	t.Parallel()

	for _, name := range All {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := Config(name)
			if err != nil {
				t.Fatalf("Config(%q): %v", name, err)
			}
			if cfg.Mode == "" {
				t.Fatal("expected mode to be set")
			}
			if got, want := cfg.Mode, expectedMode(name); got != want {
				t.Fatalf("mode = %q, want %q", got, want)
			}
		})
	}
}

func TestListDescribesEveryPreset(t *testing.T) {
	t.Parallel()

	infos := List()
	if len(infos) != len(All) {
		t.Fatalf("List returned %d presets, want %d", len(infos), len(All))
	}
	for i, info := range infos {
		if info.Name != All[i] {
			t.Errorf("preset[%d] name = %q, want %q", i, info.Name, All[i])
		}
		if info.Mode == "" {
			t.Errorf("%s mode is empty", info.Name)
		}
		if info.DefaultAction == "" {
			t.Errorf("%s default action is empty", info.Name)
		}
		if !strings.Contains(info.Reachability, "allowlist") && !strings.Contains(info.Reachability, "blocklist") {
			t.Errorf("%s reachability = %q, want allowlist/blocklist posture", info.Name, info.Reachability)
		}
	}
}

func TestPrintListIncludesEveryPreset(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := PrintList(&buf); err != nil {
		t.Fatalf("PrintList: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"NAME", "MODE", "DEFAULT ACTION", "REACHABILITY"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing header %q:\n%s", want, out)
		}
	}
	for _, name := range All {
		if !strings.Contains(out, name) {
			t.Fatalf("output missing preset %q:\n%s", name, out)
		}
	}
}

func TestCmdListsEveryPreset(t *testing.T) {
	t.Parallel()

	cmd := Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, name := range All {
		if !strings.Contains(buf.String(), name) {
			t.Fatalf("output missing preset %q:\n%s", name, buf.String())
		}
	}
}

func TestFilePresetYAMLMatchesEmbeddedBytes(t *testing.T) {
	t.Parallel()

	for _, name := range All {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := YAML(name)
			if err != nil {
				t.Fatalf("YAML(%q): %v", name, err)
			}
			want, ok := configs.Preset(name)
			if !ok {
				t.Fatalf("configs.Preset(%q) not found", name)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("YAML(%q) changed embedded bytes", name)
			}
			shipped, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", "..", "configs", name+".yaml")))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, shipped) {
				t.Fatalf("YAML(%q) differs from shipped file", name)
			}
			parsed, err := Config(name)
			if err != nil {
				t.Fatal(err)
			}
			load := config.LoadPolicyBundleBytes
			if isNamedPreset(name) {
				load = parseFilePreset
			}
			loaded, err := load(shipped)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.CanonicalPolicyHash() != loaded.CanonicalPolicyHash() {
				t.Fatal("parsed preset differs from effective shipped config")
			}
		})
	}
}

func TestUnknownPresetErrorListsAllValidNames(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", " ", "nonexistent", "Balanced", "CLAUDE-CODE"} {
		t.Run(bad, func(t *testing.T) {
			t.Parallel()

			_, err := YAML(bad)
			if err == nil {
				t.Fatal("expected error")
			}
			if _, err := Config(bad); err == nil {
				t.Fatal("expected Config error")
			}
			msg := err.Error()
			for _, name := range All {
				if !strings.Contains(msg, name) {
					t.Errorf("error %q does not list %q", msg, name)
				}
			}
		})
	}
}

func TestFilePresetRejectsUnembeddedName(t *testing.T) {
	t.Parallel()

	if _, _, err := filePreset("missing"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseConfigRejectsInvalidPresetYAML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte("")},
		{name: "document marker only", data: []byte("---\n")},
		{name: "null", data: []byte("null\n")},
		{name: "sequence", data: []byte("- mode: balanced\n")},
		{name: "multiple documents", data: []byte("mode: balanced\n---\nmode: audit\n")},
		{name: "decode error", data: []byte("mode: [\n")},
		{name: "invalid mode", data: []byte("mode: permissive\n")},
		{name: "unknown top-level field", data: []byte("mode: balanced\nunknown: true\n")},
		{name: "unknown nested field", data: []byte("response_scanning: {unknown: true}\n")},
		{name: "trailing malformed document", data: []byte("mode: balanced\n---\n[\n")},
		{name: "duplicate field", data: []byte("mode: balanced\nmode: strict\n")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for name, parse := range map[string]func([]byte) (*config.Config, error){"mode": parseConfig, "named": parseFilePreset} {
				if _, err := parse(tt.data); err == nil {
					t.Errorf("%s parser: expected error", name)
				}
			}
		})
	}
}

func isNamedPreset(name string) bool {
	switch name {
	case PresetClaudeCode, PresetCursor, PresetGenericAgent, PresetHostileModel:
		return true
	default:
		return false
	}
}

func expectedMode(name string) string {
	switch name {
	case config.ModeStrict, PresetHostileModel:
		return config.ModeStrict
	case config.ModeBalanced, PresetClaudeCode, PresetCursor, PresetGenericAgent:
		return config.ModeBalanced
	case config.ModeAudit:
		return config.ModeAudit
	default:
		panic("unexpected preset " + name)
	}
}

func TestModePresetValues(t *testing.T) {
	t.Parallel()

	strict, err := Config(config.ModeStrict)
	if err != nil {
		t.Fatalf("strict Config: %v", err)
	}
	if strict.Mode != config.ModeStrict {
		t.Errorf("strict mode = %q, want %q", strict.Mode, config.ModeStrict)
	}
	if strict.FetchProxy.Monitoring.SubdomainEntropyThreshold != 3.5 {
		t.Errorf("strict SubdomainEntropyThreshold = %v, want 3.5", strict.FetchProxy.Monitoring.SubdomainEntropyThreshold)
	}

	audit, err := Config(config.ModeAudit)
	if err != nil {
		t.Fatalf("audit Config: %v", err)
	}
	if audit.Mode != config.ModeAudit {
		t.Errorf("audit mode = %q, want %q", audit.Mode, config.ModeAudit)
	}
	if audit.Enforce == nil || *audit.Enforce {
		t.Error("audit preset should have enforce=false")
	}
	if !audit.Logging.IncludeAllowed {
		t.Error("audit preset should log allowed requests")
	}
}
