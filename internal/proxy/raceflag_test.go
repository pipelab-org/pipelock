// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build race

package proxy

// raceEnabled thins the large-payload delivery cases under the race detector,
// which slows multi-megabyte scans without adding to the transport concurrency
// coverage. TestDecodeBudgetLargeForward* and TestDecodeBudgetLargeWebSocket*
// keep their full sizes in normal builds.
const raceEnabled = true
