// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package landlockcompat

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/landlockcompat/compatest"
)

func TestReferAllowed(t *testing.T) {
	for _, tc := range compatest.ReferCases() {
		t.Run(tc.Name, func(t *testing.T) {
			got := ReferAllowed(tc.ABI, func() (int, error) { return tc.Fixed, tc.QueryErr })
			if got != tc.Allowed {
				t.Fatalf("ReferAllowed() = %v, want %v", got, tc.Allowed)
			}
		})
	}
}

// ABI 1 has no REFER right, so the answer cannot depend on errata, and the
// query must not run.
func TestReferAllowedBeforeABI2(t *testing.T) {
	for _, abi := range []int{0, 1} {
		queried := false
		if ReferAllowed(abi, func() (int, error) { queried = true; return 0x4, nil }) {
			t.Fatalf("ABI %d allowed REFER", abi)
		}
		if queried {
			t.Fatalf("ABI %d queried errata", abi)
		}
	}
}
