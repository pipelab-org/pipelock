// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"os"
	"testing"
)

// TestMain keeps capsule discovery hermetic: posture inventories the running
// user's CLAUDE_CONFIG_DIR and CODEX_HOME, so an operator's own values must not
// leak into tests that patch the home directory. Tests that need them set them
// with t.Setenv.
func TestMain(m *testing.M) {
	_ = os.Unsetenv("CLAUDE_CONFIG_DIR")
	_ = os.Unsetenv("CODEX_HOME")
	os.Exit(m.Run())
}
