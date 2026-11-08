// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

// messageWatchPolicy keeps ordinary sessions pinned while taking one coherent
// live snapshot for watch-only messages. After a mode transition, the session's
// scanner policy remains pinned and only its watch-only setting changes.
func (live MCPProxyOpts) messageWatchPolicy(pinned *MCPProxyOpts, wasWatchOnly *bool) MCPProxyOpts {
	snapshot := live.snapshotWatchPolicy()
	if snapshot.WatchOnly {
		*wasWatchOnly = true
		return snapshot
	}
	if *wasWatchOnly && pinned.watchEnforcingPolicyHash != "" {
		pinned.PolicyHash = pinned.watchEnforcingPolicyHash
		pinned.ConfigHash = pinned.watchEnforcingPolicyHash
	}
	*wasWatchOnly = false
	result := *pinned
	result.WatchOnly, result.WatchOnlyFn = false, nil
	return result
}
