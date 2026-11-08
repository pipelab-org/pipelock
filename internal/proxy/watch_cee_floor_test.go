// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestWatchAuditFloorCEEParity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		appendResult scanner.FragmentAppendResult
		matches      []scanner.DLPMatch
	}{
		{name: "path depth", appendResult: scanner.FragmentAppendResult{PathDepthExceeded: true}},
		{name: "owner mismatch", appendResult: scanner.FragmentAppendResult{OwnerMismatch: true}},
		{name: "capacity", appendResult: scanner.FragmentAppendResult{CapacityExceeded: true}},
		{name: "inspection limit", matches: []scanner.DLPMatch{{PatternName: scanner.UninspectableJSONNumberPattern}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, watch := range []bool{false, true} {
				got := ceeFragmentEvaluate(t.Context(), tc.appendResult, tc.matches, ceeStreamContext{
					WatchOnly: watch, Config: config.CrossRequestDetection{Action: config.ActionWarn},
					Logger: audit.NewNop(), Metrics: metrics.New(),
				})
				if got == nil || !got.Blocked {
					t.Fatalf("watch=%t audit floor lost: %+v", watch, got)
				}
			}
		})
	}
}
