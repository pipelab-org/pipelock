// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// InjectionWarnHook observes wording matches without receiving matched text.
type InjectionWarnHook func(context.Context, []string)

// SetInjectionWarnHook installs an audit observer. It never changes a verdict.
func (s *Scanner) SetInjectionWarnHook(hook InjectionWarnHook) {
	if hook == nil {
		s.injectionWarnHook.Store(nil)
		return
	}
	s.injectionWarnHook.Store(&hook)
}

// ForwardInjectionWarnings reports this scanner's wording observations through
// parent's hook, read at report time. A derived scanner, such as a per-agent
// profile, then reaches the runtime audit sink whichever order the hooks were
// installed in. Warn-only must never become silent for derived scanners.
func (s *Scanner) ForwardInjectionWarnings(parent *Scanner) {
	if s == nil || parent == nil || parent == s {
		return
	}
	s.SetInjectionWarnHook(func(ctx context.Context, names []string) {
		parent.ReportInjectionWarnings(ctx, names)
	})
	// External checker outcomes follow the same parent, so a profile's
	// checker failures are never silent either.
	s.SetInjectionCheckerHook(func(ctx context.Context, ev InjectionCheckerEvent) {
		parent.ReportInjectionChecker(ctx, ev)
	})
}

// PromptInjectionMode is the immutable wording policy of this scanner snapshot.
func (s *Scanner) PromptInjectionMode() string {
	if s == nil || s.injectionMode == "" {
		return config.ActionBlock
	}
	return s.injectionMode
}

type injectionSurfaceKey struct{}

// WithInjectionSurface labels ctx with the wording surface being scanned.
// The label can only lower this scanner's wording mode for that surface,
// following the surface selection compiled into the scanner's own policy
// snapshot; it never raises it above the global setting.
func WithInjectionSurface(ctx context.Context, surface string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, injectionSurfaceKey{}, surface)
}

// InjectionSurfaceFromContext returns the surface label set by
// WithInjectionSurface, or empty.
func InjectionSurfaceFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	surface, _ := ctx.Value(injectionSurfaceKey{}).(string)
	return surface
}

// InjectionPolicy is the per-surface wording policy of this scanner snapshot.
func (s *Scanner) InjectionPolicy() config.InjectionPolicy {
	if s == nil {
		return (*config.Config)(nil).InjectionPolicy()
	}
	return s.injectionPolicy
}

var injectionModeStrength = map[string]int{config.ActionAllow: 0, config.ActionWarn: 1, config.ActionBlock: 2}

// PromptInjectionModeFor is the built-in wording mode for the surface labelled
// on ctx: the global mode, lowered by that surface's selection. A surface
// selected for another checker runs no built-in wording.
func (s *Scanner) PromptInjectionModeFor(ctx context.Context) string {
	global := s.PromptInjectionMode()
	surface := InjectionSurfaceFromContext(ctx)
	if surface == "" || s == nil {
		return global
	}
	sp := s.injectionPolicy.For(surface)
	mode := config.ActionAllow
	if sp.Checker == config.InjectionCheckerBasic {
		switch sp.Mode {
		case config.InjectionModeBlock:
			mode = config.ActionBlock
		case config.InjectionModeWarn:
			mode = config.ActionWarn
		}
	}
	if injectionModeStrength[mode] < injectionModeStrength[global] {
		return mode
	}
	return global
}

// ReportInjectionWarnings records dedicated wording findings, including tool
// poisoning wording that does not use the general response regexes.
func (s *Scanner) ReportInjectionWarnings(ctx context.Context, names []string) {
	if len(names) == 0 {
		return
	}
	if hook := s.injectionWarnHook.Load(); hook != nil {
		(*hook)(ctx, names)
	}
}
