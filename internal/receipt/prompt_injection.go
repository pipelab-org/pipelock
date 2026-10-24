// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import "github.com/luckyPipewrench/pipelock/internal/config"

// WithPromptInjectionMode binds runtime wording policy to the existing signed
// pattern field. It adds no signed member or schema version. First snapshot
// wins, just as PolicyHash does, so a reload cannot relabel an earlier decision.
func WithPromptInjectionMode(opts EmitOpts, mode string) EmitOpts {
	if opts.promptInjectionModeSet {
		return opts
	}
	opts.promptInjectionModeSet = true
	opts.promptInjectionMode = mode
	return opts
}

// PromptInjectionPattern adds the bound wording policy to an existing signed
// reason field at emission, after callers have finalized their decision reason.
func (opts EmitOpts) PromptInjectionPattern(pattern string) string {
	switch opts.promptInjectionMode {
	case config.ActionAllow:
		return appendPolicyReason(pattern, "prompt_injection_detection: wording disabled")
	case config.ActionWarn:
		return appendPolicyReason(pattern, "prompt_injection_detection: wording warn-only")
	default:
		return pattern
	}
}

func appendPolicyReason(pattern, reason string) string {
	if pattern == "" {
		return reason
	}
	return pattern + "; " + reason
}
