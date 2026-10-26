// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import "testing"

// TestHooks_FindPrintsOnlyPaths checks both hooks on find output handed to
// chmod.
func TestHooks_FindPrintsOnlyPaths(t *testing.T) {
	runHookRows(t, []hookRow{
		{"perm test", "find /srv -type f -perm 0777 | xargs chmod 644", false, false, false, false},
		{"leading option", "find -L /srv -perm 0777 | xargs chmod 644", false, false, false, false},
		{"starting point", "find 777 -type f | xargs chmod -R", false, true, true, true},
		{"ls", "find /srv -perm 777 -ls | xargs chmod -R", false, true, true, true},
		{"errors joined", "find /srv -perm 777 2>&1 | xargs chmod -R", false, true, true, true},
		{"BSD option", "find -x 777 -type f | xargs chmod -R", false, true, true, true},
		{"after sudo", "sudo find /srv -perm 777 | xargs chmod -R", false, true, true, true},
	})
}
