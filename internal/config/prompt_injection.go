// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import "fmt"

// PromptInjectionDetection controls regex wording detection across transports.
// It does not control DLP, destinations, structural checks, or tool drift.
type PromptInjectionDetection struct {
	Enabled *bool `yaml:"enabled"`
	// Action is an enforcement cap. Empty/block preserves each surface's
	// existing action; warn retains findings without enforcing them.
	Action string `yaml:"action"`
	// Surfaces selects the checker and mode per surface. Omitted surfaces
	// follow Enabled and Action. See InjectionPolicy.
	Surfaces map[string]InjectionSurfaceConfig `yaml:"surfaces,omitempty" json:",omitempty"`
	// Checkers defines named external checkers a surface can select.
	Checkers map[string]InjectionCheckerConfig `yaml:"checkers,omitempty" json:",omitempty"`
}

// PromptInjectionMode returns allow for disabled wording detection, warn for
// observation only, and block for the existing per-surface enforcement policy.
func (c *Config) PromptInjectionMode() string {
	if c != nil && c.PromptInjectionDetection != nil {
		p := c.PromptInjectionDetection
		if p.Enabled != nil && !*p.Enabled {
			return ActionAllow
		}
		if p.Action == ActionWarn {
			return ActionWarn
		}
	}
	return ActionBlock
}

// PromptInjectionNotice describes the operator-selected reduction in coverage.
func (c *Config) PromptInjectionNotice() string {
	return joinInjectionNotices(c.globalPromptInjectionNotice(), c.injectionSurfaceNotice())
}

func joinInjectionNotices(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + " " + b
	}
}

func (c *Config) globalPromptInjectionNotice() string {
	switch c.PromptInjectionMode() {
	case ActionAllow:
		return "Regex prompt-injection wording detection is disabled, including core wording rules and MCP tool-description wording checks. Local stdio MCP servers no longer produce wording-based warnings or refusals. Session taint still reflects source classification and independent findings. DLP and destination controls still apply to traffic leaving the machine through Pipelock; tool policy, drift, contracts, action limits and the kill switch remain active where configured. With adaptive enforcement enabled, clean traffic no longer lowers session scores; adaptive levels recover by time only, and residual scores at normal level expire after a level_duration_seconds interval without new scored signals."
	case ActionWarn:
		return "Regex prompt-injection wording detection is warn-only, including core wording rules and MCP tool-description wording checks. Wording matches are logged without blocking, stripping, asking or producing injection-driven taint. DLP and destination controls still apply to traffic leaving the machine through Pipelock; tool policy, drift, contracts, action limits and the kill switch remain active where configured."
	default:
		return ""
	}
}

func (c *Config) validatePromptInjectionDetection() error {
	if c.PromptInjectionDetection == nil {
		return nil
	}
	switch c.PromptInjectionDetection.Action {
	case "", ActionBlock, ActionWarn:
		if err := c.validateInjectionCheckers(); err != nil {
			return err
		}
		return c.validateInjectionSurfaces()
	default:
		return fmt.Errorf("invalid prompt_injection_detection.action %q: must be block or warn", c.PromptInjectionDetection.Action)
	}
}
