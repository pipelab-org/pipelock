// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import "github.com/luckyPipewrench/pipelock/internal/config"

// WithWatchOnly binds the observation mode to the decision's existing signed
// reason. The first snapshot wins across reload and outcome emission, including
// an explicit false. The frozen v1 signing projection remains unchanged.
func WithWatchOnly(opts EmitOpts, enabled bool) EmitOpts {
	if opts.watchOnlySet {
		return opts
	}
	opts.watchOnlySet, opts.watchOnly = true, enabled
	return opts
}

// WatchOnlyPattern marks the final action without changing its verdict. An
// observed policy refusal must have an allow or warn verdict at its producer;
// a block remains a real enforced exception, never a forwarded request.
func (opts EmitOpts) WatchOnlyPattern(pattern string) string {
	if !opts.watchOnly {
		return pattern
	}
	if opts.Verdict == config.ActionBlock {
		return appendPolicyReason(pattern, "watch_only: enforced in watch-only")
	}
	return appendPolicyReason(pattern, "watch_only: observation")
}
