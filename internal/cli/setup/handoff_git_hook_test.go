// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import "testing"

// TestHooks_GitHandOffs checks both hooks on git commands given their flags
// by another command.
func TestHooks_GitHandOffs(t *testing.T) {
	runHookRows(t, []hookRow{
		{"flags piped to xargs", "echo -f -d | xargs git clean", false, true, true, true},
		{"flags piped, text not split", "echo -f -d $x | xargs git clean", false, true, true, true},
		{"own flag, handed flag", "echo -d | xargs git clean -f", false, true, true, true},
		{"here-string", "git clean <<<'-f -d'", true, false, true, false},
		// Benign twins.
		{"dry run", "echo -n -d | xargs git clean", false, false, false, false},
		{"own dry run", "echo -d | xargs git clean -n", false, false, false, false},
	})
}
