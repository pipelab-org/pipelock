// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import "testing"

// TestHooks_SplitSpellings checks that both hooks deny each command with the
// default config and with configs/strict.yaml, and allow a benign twin.
func TestHooks_SplitSpellings(t *testing.T) {
	runHookRows(t, []hookRow{
		{"git clean -f -d", "git clean -f -d", true, false, true, false},
		{"git clean -d -f", "git clean -d -f", true, false, true, false},
		{"push a plus ref", "git push origin +main", true, false, true, false},
		{"npm i", "npm i left-pad", true, false, true, false},
		{"pnpm add", "pnpm add left-pad", true, false, true, false},
		{"mkfs -t", "mkfs -t ext4 /dev/sdb1", true, false, true, false},
		{"wipefs", "wipefs -a /dev/sdb", true, false, true, false},
		{"base64 to /bin/sh", "echo Zm9v | base64 -d | /bin/sh", true, false, true, false},
		{"chmod -R a+rwx", "chmod -R a+rwx /srv", true, false, true, false},
		// Benign twins.
		{"git clean dry run", "git clean -n -d", false, false, false, false},
		{"npm ls", "npm ls left-pad", false, false, false, false},
		{"chmod a+r", "chmod a+r /srv/x", false, false, false, false},
	})
}
