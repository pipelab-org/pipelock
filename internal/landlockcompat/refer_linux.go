// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package landlockcompat holds shared kernel compatibility decisions.
package landlockcompat

// ReferAllowed reports whether REFER may be granted. ABI 2 introduced REFER;
// erratum 3 fixes access widening through disconnected directories. Errata use
// bit N-1 for erratum N. A failed query cannot confirm the fix.
// See https://docs.kernel.org/userspace-api/landlock.html#landlock-errata.
func ReferAllowed(abi int, errata func() (int, error)) bool {
	if abi < 2 {
		return false
	}
	fixed, err := errata()
	return err == nil && fixed&(1<<(3-1)) != 0
}
