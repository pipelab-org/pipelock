// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import "testing"

func TestHookTimeoutsRemain10s(t *testing.T) {
	if claudeHookTimeout != 10 {
		t.Errorf("claude hook timeout = %d, want 10", claudeHookTimeout)
	}
	if cursorHookTimeout != 10 {
		t.Errorf("cursor hook timeout = %d, want 10", cursorHookTimeout)
	}
}
