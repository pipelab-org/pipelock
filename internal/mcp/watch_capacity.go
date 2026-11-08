// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

// A session admitted while watching without a recorder must not silently lose
// its stateful controls if enforcement is subsequently enabled. Ordinary
// startup and callers that intentionally use stateless scanning stay unchanged.
func mcpWatchCapacityAvailable(opts MCPProxyOpts, n int) bool {
	if !opts.watchMissingRecorder || opts.Rec != nil {
		return true
	}
	if !opts.watchOnly() {
		return false
	}
	opts.recordWatch("session", "session inspection capacity unavailable", "uninspected", int64(n), false)
	return true
}
