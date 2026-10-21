// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"os"
	"testing"
)

// TestMain keeps capsule discovery hermetic: posture inventories the running
// user's CLAUDE_CONFIG_DIR, so an operator's own value must not leak into tests
// that patch the home directory. Tests that need it set it with t.Setenv.
func TestMain(m *testing.M) {
	_ = os.Unsetenv("CLAUDE_CONFIG_DIR")
	os.Exit(m.Run())
}
