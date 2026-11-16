// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Injection checker surfaces that accept a per-surface selection. Other
// wording consumers (HTTP, WebSocket, A2A, MCP input, Scan API) keep following
// the global prompt_injection_detection setting and report that they do.
const (
	InjectionSurfaceMCPToolResult      = "mcp_tool_result"
	InjectionSurfaceMCPToolDescription = "mcp_tool_description"
)

// InjectionCheckerBasic names the built-in wording checker.
const InjectionCheckerBasic = "basic"

// Injection surface modes. Off performs no assessment, warn records without
// changing delivery, block applies the surface's existing enforcement.
const (
	InjectionModeOff   = "off"
	InjectionModeWarn  = "warn"
	InjectionModeBlock = "block"
)

// Injection policy sources, reported by diagnostics.
const (
	InjectionPolicySourceLegacy  = "legacy"
	InjectionPolicySourceSurface = "surface"
)

// InjectionSurfaces lists the surfaces that accept a selection, in a stable order.
func InjectionSurfaces() []string {
	return []string{InjectionSurfaceMCPToolResult, InjectionSurfaceMCPToolDescription}
}

// InjectionSurfaceConfig selects the checker and mode for one surface.
type InjectionSurfaceConfig struct {
	// Checker names the checker that decides this surface. Empty means basic.
	Checker string `yaml:"checker,omitempty" json:"checker,omitempty"`
	// Mode is off, warn or block. Empty is rejected: a selection must say
	// what it does.
	Mode string `yaml:"mode" json:"mode"`
}

// InjectionSurfacePolicy is the compiled selection for one surface.
type InjectionSurfacePolicy struct {
	Surface string
	Checker string
	Mode    string
	Source  string
}

// InjectionPolicy is the immutable effective per-surface wording policy
// compiled from prompt_injection_detection. It never grants permission and
// never changes DLP, destination, tool-policy or structural tool checks.
type InjectionPolicy struct {
	// Global is the legacy wording mode (allow, warn or block) that every
	// surface without a selection follows.
	Global   string
	surfaces map[string]InjectionSurfacePolicy
	digest   string
}

// legacyInjectionMode maps the legacy global setting to a surface mode.
func legacyInjectionMode(global string) string {
	switch global {
	case ActionAllow:
		return InjectionModeOff
	case ActionWarn:
		return InjectionModeWarn
	default:
		return InjectionModeBlock
	}
}

var injectionModeRank = map[string]int{InjectionModeOff: 0, InjectionModeWarn: 1, InjectionModeBlock: 2}

// For returns the effective selection for surface. Unknown surfaces follow
// the global setting through the basic checker.
func (p InjectionPolicy) For(surface string) InjectionSurfacePolicy {
	if sp, ok := p.surfaces[surface]; ok {
		return sp
	}
	return InjectionSurfacePolicy{
		Surface: surface, Checker: InjectionCheckerBasic,
		Mode: legacyInjectionMode(p.Global), Source: InjectionPolicySourceLegacy,
	}
}

// Surfaces returns every selectable surface's effective policy in stable order.
func (p InjectionPolicy) Surfaces() []InjectionSurfacePolicy {
	out := make([]InjectionSurfacePolicy, 0, len(InjectionSurfaces()))
	for _, s := range InjectionSurfaces() {
		out = append(out, p.For(s))
	}
	return out
}

// Digest identifies the effective policy. Equal digests mean equal behavior.
func (p InjectionPolicy) Digest() string { return p.digest }

// Selected reports whether any surface has an explicit selection.
func (p InjectionPolicy) Selected() bool { return len(p.surfaces) > 0 }

// InjectionPolicy compiles the effective per-surface wording policy. It
// assumes the config has been validated; invalid entries are skipped, never
// widened.
func (c *Config) InjectionPolicy() InjectionPolicy {
	p := InjectionPolicy{Global: c.PromptInjectionMode(), surfaces: map[string]InjectionSurfacePolicy{}}
	if c != nil && c.PromptInjectionDetection != nil {
		for name, sc := range c.PromptInjectionDetection.Surfaces {
			if !slices.Contains(InjectionSurfaces(), name) {
				continue
			}
			if _, ok := injectionModeRank[sc.Mode]; !ok {
				continue
			}
			checker := sc.Checker
			if checker == "" {
				checker = InjectionCheckerBasic
			}
			p.surfaces[name] = InjectionSurfacePolicy{Surface: name, Checker: checker, Mode: sc.Mode, Source: InjectionPolicySourceSurface}
		}
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "pipelock.injection-policy/v1\x00global=%s\x00", p.Global)
	for _, sp := range p.Surfaces() {
		_, _ = fmt.Fprintf(h, "%s=%s/%s\x00", sp.Surface, sp.Checker, sp.Mode)
	}
	p.digest = hex.EncodeToString(h.Sum(nil))
	return p
}

// validateInjectionSurfaces rejects selections with a diagnostic that names
// the surface, the active binding and the remedy.
func (c *Config) validateInjectionSurfaces() error {
	if c.PromptInjectionDetection == nil {
		return nil
	}
	names := make([]string, 0, len(c.PromptInjectionDetection.Surfaces))
	for name := range c.PromptInjectionDetection.Surfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	global := c.PromptInjectionMode()
	for _, name := range names {
		sc := c.PromptInjectionDetection.Surfaces[name]
		field := "prompt_injection_detection.surfaces." + name
		if !slices.Contains(InjectionSurfaces(), name) {
			return fmt.Errorf("%s: surface is not selectable; selectable surfaces are %s, and every other wording consumer follows prompt_injection_detection.enabled and action", field, strings.Join(InjectionSurfaces(), ", "))
		}
		rank, ok := injectionModeRank[sc.Mode]
		if !ok {
			return fmt.Errorf("%s.mode %q: must be off, warn or block", field, sc.Mode)
		}
		checker := sc.Checker
		if checker == "" {
			checker = InjectionCheckerBasic
		}
		if checker != InjectionCheckerBasic {
			return fmt.Errorf("%s.checker %q: unknown checker; this build selects only %q", field, sc.Checker, InjectionCheckerBasic)
		}
		// The global setting caps the built-in checker everywhere: a surface
		// may lower it, never raise it. Raising would need the wording rules
		// the global switch turned off, so the two settings would conflict.
		if legacy := legacyInjectionMode(global); rank > injectionModeRank[legacy] {
			return fmt.Errorf("%s.mode %q conflicts with the global wording setting (%s): the basic checker cannot exceed it on one surface; raise prompt_injection_detection.enabled/action or lower this surface to %s", field, sc.Mode, legacy, legacy)
		}
	}
	return nil
}

// injectionSurfaceNotice describes selections that reduce coverage on a
// surface relative to the global setting. Empty when nothing is reduced.
func (c *Config) injectionSurfaceNotice() string {
	p := c.InjectionPolicy()
	legacy := legacyInjectionMode(p.Global)
	var parts []string
	for _, sp := range p.Surfaces() {
		if sp.Source == InjectionPolicySourceSurface && injectionModeRank[sp.Mode] < injectionModeRank[legacy] {
			parts = append(parts, fmt.Sprintf("%s=%s", sp.Surface, sp.Mode))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf("Prompt-injection wording assessment is reduced on %s (global setting: %s). Off performs no wording assessment on that surface; warn records findings without blocking or producing injection-driven taint. Structural tool checks, drift, DLP, destination controls and tool policy remain active.", strings.Join(parts, ", "), legacy)
}

func cloneInjectionSurfaces(in map[string]InjectionSurfaceConfig) map[string]InjectionSurfaceConfig {
	if in == nil {
		return nil
	}
	out := make(map[string]InjectionSurfaceConfig, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// injectionSurfaceReloadWarnings reports every surface whose effective mode
// is lowered or whose checker changes on reload, naming old and new bindings.
func injectionSurfaceReloadWarnings(old, updated *Config) []ReloadWarning {
	oldP, newP := old.InjectionPolicy(), updated.InjectionPolicy()
	var out []ReloadWarning
	for _, surface := range InjectionSurfaces() {
		before, after := oldP.For(surface), newP.For(surface)
		lowered := injectionModeRank[after.Mode] < injectionModeRank[before.Mode]
		if !lowered && before.Checker == after.Checker {
			continue
		}
		out = append(out, ReloadWarning{
			Field: "prompt_injection_detection.surfaces." + surface,
			Message: fmt.Sprintf("injection checker binding for %s changed from %s/%s (%s) to %s/%s (%s)",
				surface, before.Checker, before.Mode, before.Source, after.Checker, after.Mode, after.Source),
		})
	}
	return out
}
