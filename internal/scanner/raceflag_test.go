// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build race

package scanner

// raceEnabled skips wall-clock guards, which the race detector slows
// several times over.
const raceEnabled = true
