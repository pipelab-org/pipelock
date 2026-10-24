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
}

// PromptInjectionMode is the immutable wording policy of this scanner snapshot.
func (s *Scanner) PromptInjectionMode() string {
	if s == nil || s.injectionMode == "" {
		return config.ActionBlock
	}
	return s.injectionMode
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
