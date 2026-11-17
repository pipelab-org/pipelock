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
// wording consumers (WebSocket, SSE and A2A) keep following
// the global prompt_injection_detection setting and report that they do.
const (
	InjectionSurfaceMCPToolResult      = "mcp_tool_result"
	InjectionSurfaceMCPToolDescription = "mcp_tool_description"
	InjectionSurfaceHTTPResponse       = "http_response"
	InjectionSurfaceBrowserShield      = "browser_shield"
	InjectionSurfaceHTTPRequestBody    = "http_request_body"
	InjectionSurfaceMCPToolInput       = "mcp_tool_input"
	InjectionSurfaceScanAPI            = "scan_api"
	InjectionSurfaceHookToolInput      = "hook_tool_input"
	InjectionSurfaceHookToolResult     = "hook_tool_result"
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
	return []string{
		InjectionSurfaceMCPToolResult, InjectionSurfaceMCPToolDescription,
		InjectionSurfaceHTTPResponse, InjectionSurfaceBrowserShield, InjectionSurfaceHTTPRequestBody,
		InjectionSurfaceMCPToolInput, InjectionSurfaceScanAPI, InjectionSurfaceHookToolInput, InjectionSurfaceHookToolResult,
	}
}

// InjectionSurfaceConfig selects the checker and mode for one surface.
type InjectionSurfaceConfig struct {
	// Checker names the checker that decides this surface. Empty means basic.
	Checker string `yaml:"checker,omitempty" json:"checker,omitempty"`
	// Mode is off, warn or block. Empty is rejected: a selection must say
	// what it does.
	Mode string `yaml:"mode" json:"mode"`
	// Watch names a checker that assesses the same content and records its
	// outcome without changing delivery. Empty means none.
	Watch string `yaml:"watch,omitempty" json:"watch,omitempty"`
}

// InjectionSurfacePolicy is the compiled selection for one surface.
type InjectionSurfacePolicy struct {
	Surface string
	Checker string
	Mode    string
	Watch   string
	Source  string
}

// Binding renders the selection for diagnostics: checker/mode, the watch
// checker when set, and the setting that owns it.
func (sp InjectionSurfacePolicy) Binding() string {
	watch := ""
	if sp.Watch != "" {
		watch = " watch=" + sp.Watch
	}
	return fmt.Sprintf("%s/%s%s (%s)", sp.Checker, sp.Mode, watch, sp.Source)
}

// External reports whether a checker other than the built-in decides.
func (sp InjectionSurfacePolicy) External() bool { return sp.Checker != InjectionCheckerBasic }

// InjectionPolicy is the immutable effective per-surface wording policy
// compiled from prompt_injection_detection. It never grants permission and
// never changes DLP, destination, tool-policy or structural tool checks.
type InjectionPolicy struct {
	// Global is the legacy wording mode (allow, warn or block) that every
	// surface without a selection follows.
	Global   string
	surfaces map[string]InjectionSurfacePolicy
	checkers map[string]InjectionCheckerConfig
	digest   string
}

// Checker returns a copy of the named checker definition.
func (p InjectionPolicy) Checker(name string) (InjectionCheckerConfig, bool) {
	cc, ok := p.checkers[name]
	if !ok {
		return InjectionCheckerConfig{}, false
	}
	return cc.clone(), true
}

// CheckerNames lists defined external checkers in stable order.
func (p InjectionPolicy) CheckerNames() []string { return sortedCheckerNames(p.checkers) }

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
		p.checkers = cloneInjectionCheckers(c.PromptInjectionDetection.Checkers)
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
			p.surfaces[name] = InjectionSurfacePolicy{Surface: name, Checker: checker, Mode: sc.Mode, Watch: sc.Watch, Source: InjectionPolicySourceSurface}
		}
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "pipelock.injection-policy/v1\x00global=%s\x00", p.Global)
	for _, sp := range p.Surfaces() {
		_, _ = fmt.Fprintf(h, "%s=%s/%s/watch=%s\x00", sp.Surface, sp.Checker, sp.Mode, sp.Watch)
	}
	for _, name := range sortedCheckerNames(p.checkers) {
		_, _ = fmt.Fprintf(h, "checker %s: %s\x00", name, p.checkers[name].canonicalString())
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
		defined := c.PromptInjectionDetection.Checkers
		if _, ok := defined[checker]; checker != InjectionCheckerBasic && !ok {
			return fmt.Errorf("%s.checker %q: unknown checker; use %q or a name defined under prompt_injection_detection.checkers", field, sc.Checker, InjectionCheckerBasic)
		}
		if sc.Watch != "" {
			if _, ok := defined[sc.Watch]; !ok {
				return fmt.Errorf("%s.watch %q: unknown checker; watch names a checker defined under prompt_injection_detection.checkers", field, sc.Watch)
			}
			if sc.Watch == checker {
				return fmt.Errorf("%s.watch %q: the watch checker must differ from the deciding checker", field, sc.Watch)
			}
		}
		// Tool descriptions reach an external checker only through the tool
		// scanner. Without it the checker would never be called and the
		// descriptions would pass unassessed.
		if name == InjectionSurfaceMCPToolDescription && (checker != InjectionCheckerBasic && sc.Mode != InjectionModeOff || sc.Watch != "") && !c.MCPToolScanning.Enabled {
			return fmt.Errorf("%s: an external checker on tool descriptions needs mcp_tool_scanning.enabled: true, which is what reads the descriptions", field)
		}
		needsExternal := (checker != InjectionCheckerBasic && sc.Mode != InjectionModeOff) || sc.Watch != ""
		if needsExternal && name == InjectionSurfaceHTTPRequestBody && !c.RequestBodyScanning.Enabled {
			return fmt.Errorf("%s: an external checker on request bodies needs request_body_scanning.enabled: true, which reads the body", field)
		}
		if needsExternal && name == InjectionSurfaceMCPToolInput && !c.MCPInputScanning.Enabled {
			return fmt.Errorf("%s: an external checker on MCP input needs mcp_input_scanning.enabled: true, which reads requests", field)
		}
		// The global setting caps the built-in checker everywhere: a surface
		// may lower it, never raise it. Raising would need the wording rules
		// the global switch turned off, so the two settings would conflict.
		// An external checker's mode is its own (it runs no wording rules).
		if legacy := legacyInjectionMode(global); checker == InjectionCheckerBasic && rank > injectionModeRank[legacy] {
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
	var parts, external []string
	offHost := map[string][]string{}
	for _, sp := range p.Surfaces() {
		if sp.External() {
			external = append(external, fmt.Sprintf("%s by %s in %s mode", sp.Surface, sp.Checker, sp.Mode))
		} else if sp.Source == InjectionPolicySourceSurface && injectionModeRank[sp.Mode] < injectionModeRank[legacy] {
			parts = append(parts, fmt.Sprintf("%s=%s", sp.Surface, sp.Mode))
		}
		for _, name := range []string{sp.Checker, sp.Watch} {
			if cc, ok := p.checkers[name]; ok && cc.SendsOffHost() && (sp.Mode != InjectionModeOff || name == sp.Watch) {
				offHost[name] = append(offHost[name], sp.Surface)
			}
		}
	}
	var notices []string
	if len(parts) > 0 {
		notices = append(notices, fmt.Sprintf("Prompt-injection wording assessment is reduced on %s (global setting: %s). Off performs no wording assessment on that surface; warn records findings without blocking or producing injection-driven taint. Structural tool checks, drift, DLP, destination controls and tool policy remain active.", strings.Join(parts, ", "), legacy))
	}
	if len(external) > 0 {
		notices = append(notices, fmt.Sprintf("External injection checkers decide %s. The built-in wording rules do not run on those surfaces and are never used as a fallback: in block mode, content the checker could not assess is withheld; in warn mode it is delivered marked unassessed.", strings.Join(external, ", ")))
	}
	for _, name := range sortedKeys(offHost) {
		notices = append(notices, fmt.Sprintf("Injection checker %s sends content from %s to %s, off this machine.", name, strings.Join(offHost[name], ", "), p.checkers[name].EndpointHost()))
	}
	return strings.Join(notices, " ")
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
		if !lowered && before.Checker == after.Checker && before.Watch == after.Watch {
			continue
		}
		out = append(out, ReloadWarning{
			Field:   "prompt_injection_detection.surfaces." + surface,
			Message: fmt.Sprintf("injection checker binding for %s changed from %s to %s", surface, before.Binding(), after.Binding()),
		})
	}
	for _, name := range newP.CheckerNames() {
		was, existed := oldP.checkers[name]
		now := newP.checkers[name]
		if !existed || was.canonicalString() == now.canonicalString() {
			continue
		}
		out = append(out, ReloadWarning{
			Field:   injectionCheckerNamePrefix + name,
			Message: fmt.Sprintf("injection checker %s definition changed (endpoint %s, type %s); new assessments use the new definition", name, now.EndpointHost(), now.Type),
		})
	}
	return out
}
