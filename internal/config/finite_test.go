// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Each float declaration in the config schema has a YAML load case, including
// the pointer in Sentry and the map nested inside named agent profiles.
func TestLoadNonFiniteFloats(t *testing.T) {
	t.Parallel()
	fields := []struct {
		path  string
		yaml  string
		valid string
	}{
		{"fetch_proxy.monitoring.entropy_threshold", "fetch_proxy:\n  monitoring:\n    entropy_threshold: %s\n", "4.5"},
		{"fetch_proxy.monitoring.subdomain_entropy_threshold", "fetch_proxy:\n  monitoring:\n    subdomain_entropy_threshold: %s\n", "4"},
		{"adaptive_enforcement.escalation_threshold", "adaptive_enforcement:\n  escalation_threshold: %s\n", "5"},
		{"adaptive_enforcement.decay_per_clean_request", "adaptive_enforcement:\n  decay_per_clean_request: %s\n", "0.5"},
		{"request_body_scanning.content_entropy_threshold", "request_body_scanning:\n  content_entropy_threshold: %s\n", "7"},
		{"cross_request_detection.entropy_budget.bits_per_window", "cross_request_detection:\n  entropy_budget:\n    bits_per_window: %s\n", "1024"},
		{"sentry.sample_rate", "sentry:\n  sample_rate: %s\n", "0.5"},
		{`agents["agent-a"].budget.cost_multipliers["api.vendor.example"]`, "agents:\n  agent-a:\n    budget:\n      cost_multipliers:\n        api.vendor.example: %s\n", "1"},
		{"behavioral_baseline.sensitivity_sigma", "behavioral_baseline:\n  sensitivity_sigma: %s\n", "2"},
		{"learn.inference.normalization.entropy_threshold_bits", "learn:\n  inference:\n    normalization:\n      entropy_threshold_bits: %s\n", "3"},
		{"learn.inference.normalization.tail_promotion_block_pct", "learn:\n  inference:\n    normalization:\n      tail_promotion_block_pct: %s\n", "5"},
	}
	for _, field := range fields {
		t.Run(field.path, func(t *testing.T) {
			for _, value := range []string{".nan", ".inf", "-.inf", field.valid} {
				t.Run(value, func(t *testing.T) {
					data := []byte(fmt.Sprintf(field.yaml, value))
					for name, load := range map[string]func([]byte) (*Config, error){
						"runtime": LoadBytes,
						"policy":  LoadPolicyBundleBytes,
					} {
						t.Run(name, func(t *testing.T) {
							cfg, err := load(data)
							if value == field.valid {
								if err != nil || cfg == nil {
									t.Fatalf("finite control did not load: %v", err)
								}
								return
							}
							want := field.path + " must be a finite number"
							if cfg != nil || err == nil || !strings.Contains(err.Error(), want) {
								t.Fatalf("Load(%s): config returned=%t, error=%v; want %q", value, cfg != nil, err, want)
							}
						})
					}
				})
			}
		})
	}
}

func TestLoadNonFiniteFloatsEnabledAndDisabled(t *testing.T) {
	t.Parallel()
	for _, enabled := range []bool{false, true} {
		for _, value := range []string{".nan", ".inf", "-.inf", "5"} {
			t.Run(fmt.Sprintf("enabled=%t/%s", enabled, value), func(t *testing.T) {
				data := fmt.Sprintf("session_profiling:\n  enabled: true\nadaptive_enforcement:\n  enabled: %t\n  escalation_threshold: %s\n", enabled, value)
				cfg, err := LoadBytes([]byte(data))
				if value == "5" {
					if err != nil || cfg.AdaptiveEnforcement.Enabled != enabled || cfg.AdaptiveEnforcement.EscalationThreshold != 5 {
						t.Fatalf("finite control: cfg=%v, err=%v", cfg, err)
					}
					return
				}
				if cfg != nil || err == nil || !strings.Contains(err.Error(), "adaptive_enforcement.escalation_threshold must be a finite number") {
					t.Fatalf("non-finite threshold accepted or wrong error: %v", err)
				}
			})
		}
	}
}

func TestLoadNonFiniteFloatsFileEntrypoints(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(path, []byte("adaptive_enforcement:\n  escalation_threshold: .nan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, load := range map[string]func(string) (*Config, error){
		"load":       Load,
		"runtime":    LoadForRuntime,
		"rules":      LoadForRules,
		"inspection": LoadForInspection,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := load(path)
			if cfg != nil || err == nil || !strings.Contains(err.Error(), "adaptive_enforcement.escalation_threshold must be a finite number") {
				t.Fatalf("non-finite threshold accepted or wrong error: %v", err)
			}
		})
	}
}

func TestValidateNonFiniteFloats(t *testing.T) {
	t.Parallel()
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 5} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			cfg := Defaults()
			cfg.AdaptiveEnforcement.EscalationThreshold = value
			err := cfg.Validate()
			if value == 5 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || err.Error() != "adaptive_enforcement.escalation_threshold must be a finite number" {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}
}

func TestValidateFiniteValueContainers(t *testing.T) {
	t.Parallel()
	type leaf struct {
		Number float64 `yaml:"number,omitempty"`
	}
	for _, tc := range []struct {
		name  string
		value any
		path  string
	}{
		{"pointer", &leaf{Number: math.NaN()}, "root.number"},
		{"slice", []leaf{{Number: math.Inf(1)}}, "root[0].number"},
		{"array", [1]*leaf{{Number: math.Inf(-1)}}, "root[0].number"},
		{"map", map[string][]*leaf{"entry": {{Number: math.NaN()}}}, `root["entry"][0].number`},
		{"interface", map[string]any{"entry": float32(math.Inf(1))}, `root["entry"]`},
		{"map key", map[float64]string{math.NaN(): "value"}, "root[NaN]"},
		{"inline", struct {
			Leaf leaf `yaml:",inline"`
		}{Leaf: leaf{Number: math.NaN()}}, "root.number"},
		{"default name", struct{ Number float64 }{Number: math.NaN()}, "root.number"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFiniteValue(reflect.ValueOf(tc.value), "root")
			if err == nil || err.Error() != tc.path+" must be a finite number" {
				t.Fatalf("validateFiniteValue() = %v, want path %q", err, tc.path)
			}
		})
	}
	t.Run("finite and absent values", func(t *testing.T) {
		value := struct {
			Pointer *float64       `yaml:"pointer"`
			Items   []leaf         `yaml:"items"`
			Map     map[string]any `yaml:"map"`
			Array   [1]leaf        `yaml:"array"`
			Numeric map[int]leaf   `yaml:"numeric"`
			Ignored float64        `yaml:"-"`
			hidden  float64
		}{
			Items:   []leaf{{Number: math.MaxFloat64}, {Number: math.SmallestNonzeroFloat64}, {Number: -math.MaxFloat64}},
			Map:     map[string]any{"nil": nil, "finite": float32(math.MaxFloat32)},
			Numeric: map[int]leaf{1: {Number: 2}},
			Ignored: math.NaN(),
			hidden:  math.Inf(1),
		}
		if err := validateFiniteValue(reflect.ValueOf(value), "root"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestReloaderRejectsNonFiniteFloats(t *testing.T) {
	t.Parallel()
	for _, trigger := range []ReloadTrigger{ReloadTriggerFile, ReloadTriggerSignal} {
		t.Run(fmt.Sprint(trigger), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			r := NewReloader(path)
			defer r.Close()
			write := func(value string) {
				t.Helper()
				data := "session_profiling:\n  enabled: true\nadaptive_enforcement:\n  enabled: true\n  escalation_threshold: " + value + "\n"
				if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
				r.tryReload(trigger)
			}
			write("5")
			active := <-r.Changes()
			initial := <-r.Reloads()
			if initial.Err != nil || initial.Config != active || active.AdaptiveEnforcement.EscalationThreshold != 5 {
				t.Fatalf("initial load: %+v", initial)
			}
			for _, value := range []string{".nan", ".inf", "-.inf"} {
				write(value)
				event := <-r.Reloads()
				if event.Err == nil || event.Config != nil || event.SourceHash == "" || event.SourceHash == initial.SourceHash || event.Trigger != trigger {
					t.Fatalf("invalid reload outcome: %+v", event)
				}
				if !strings.Contains(event.Err.Error(), "adaptive_enforcement.escalation_threshold must be a finite number") {
					t.Fatalf("reload error does not name field: %v", event.Err)
				}
				select {
				case cfg := <-r.Changes():
					t.Fatalf("invalid reload replaced active config: %v", cfg)
				default:
				}
				if active.AdaptiveEnforcement.EscalationThreshold != 5 || !active.AdaptiveEnforcement.Enabled {
					t.Fatal("rejected reload changed the active configuration")
				}
			}
			// A later valid change and an unchanged reload still publish normally.
			for range 2 {
				write("8")
				active = <-r.Changes()
				event := <-r.Reloads()
				if event.Err != nil || event.Config != active || active.AdaptiveEnforcement.EscalationThreshold != 8 {
					t.Fatalf("valid reload: %+v", event)
				}
			}
		})
	}
}
