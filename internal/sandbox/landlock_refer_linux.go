// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"

	"github.com/luckyPipewrench/pipelock/internal/landlockcompat"
)

// landlockErrata reports the kernel's fixed Landlock errata bitmask. It is a
// variable so tests can simulate kernels without a given fix.
var landlockErrata = llsys.LandlockGetErrata

func referAllowed(abi int, errata func() (int, error)) bool {
	return landlockcompat.ReferAllowed(abi, errata)
}
