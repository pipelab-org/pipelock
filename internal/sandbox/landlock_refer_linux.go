// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"

// landlockErrata reports the kernel's fixed Landlock errata bitmask. It is a
// variable so tests can simulate kernels without a given fix.
var landlockErrata = llsys.LandlockGetErrata

// landlockErratumDisconnectedDirs is the errata bit for Landlock erratum 3,
// disconnected directory handling (bit N-1 for erratum N, as go-landlock uses
// 0x2 for erratum 2).
const landlockErratumDisconnectedDirs = 0x4

// referAllowed reports whether REFER may be granted: Landlock ABI 2 or newer
// and erratum 3 reported fixed. An errata query failure counts as not fixed.
func referAllowed(abi int, errata func() (int, error)) bool {
	if abi < 2 {
		return false
	}
	fixed, err := errata()
	if err != nil {
		return false
	}
	return fixed&landlockErratumDisconnectedDirs != 0
}
