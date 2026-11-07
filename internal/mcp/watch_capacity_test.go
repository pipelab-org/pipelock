// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"sync/atomic"
	"testing"
)

func TestWatchCapacityModeMatrix(t *testing.T) {
	var enabled atomic.Bool
	opts := MCPProxyOpts{WatchOnlyFn: enabled.Load, watchMissingRecorder: true}
	for _, mode := range []bool{false, true, true, false, false} {
		enabled.Store(mode)
		if got := mcpWatchCapacityAvailable(opts, 17); got != mode {
			t.Fatalf("watch=%v available=%v", mode, got)
		}
	}
	opts.watchMissingRecorder = false
	if !mcpWatchCapacityAvailable(opts, 17) {
		t.Fatal("ordinary stateless behavior changed")
	}
}
