// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import "testing"

// TestHooks_FindStartingPoints checks both hooks on finds whose starting
// point is . or names a path, and on words outside find's arguments.
func TestHooks_FindStartingPoints(t *testing.T) {
	runHookRows(t, []hookRow{
		{"dot", "find . -type f -perm 0777 | xargs chmod 644", false, false, false, false},
		{"starting point naming path", "find ./mypath -perm 0777 | xargs chmod 644", false, false, false, false},
		{"dot sourced first", ". ./x; find . -perm 777 | xargs chmod -R", false, true, true, true},
		{"PATH after env", "env PATH=/tmp find . -perm 777 | xargs chmod -R", false, true, true, true},
		{"& ends a find", "find . -name a& find . -perm 0777 | xargs chmod 644", false, false, false, false},
		{"word after &", "find . -perm 1&x; find . -perm 777 | xargs chmod -R", false, true, true, true},
		{"word after |", "find . -perm 1|x; find . -perm 777 | xargs chmod -R", false, true, true, true},
		{"comma before a starting point", "find . , 777 -type f | xargs chmod -R", false, true, true, true},
		{"two lines", "find . -name x\nfind . -perm 0777 | xargs chmod 644", false, false, false, false},
		{"comment after find", "find . -perm 777 | xargs chmod -R # note", false, true, true, true},
	})
}
