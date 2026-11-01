// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package compatest supplies shared REFER parity cases for Guard and sandbox.
package compatest

import "errors"

// ReferCase is one kernel input and its expected REFER grant decision.
type ReferCase struct {
	Name     string
	ABI      int
	Fixed    int
	QueryErr error
	Allowed  bool
}

// ReferCases covers the erratum-3 contract at Guard's minimum and newer ABIs.
func ReferCases() []ReferCase {
	return []ReferCase{
		{Name: "minimum fixed", ABI: 5, Fixed: 0x4, Allowed: true},
		{Name: "fixed with others", ABI: 9, Fixed: 0xf, Allowed: true},
		{Name: "missing fix", ABI: 9, Fixed: 0x3},
		{Name: "no errata", ABI: 5},
		{Name: "query fails despite bit", ABI: 9, Fixed: 0x4, QueryErr: errors.New("errata query unavailable")},
	}
}
