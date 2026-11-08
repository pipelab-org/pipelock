// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestAdmissionResidualProse(t *testing.T) {
	for _, expr := range admissionProbePatterns[:4] {
		for _, inbound := range []bool{false, true} {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Configured probe", Regex: expr, Severity: config.SeverityHigh})
			sc := MustNew(cfg)
			ctx := context.Background()
			if inbound {
				ctx = WithInboundDirection(ctx)
			}
			got := sc.ScanTextForDLP(ctx, strings.Repeat("The quarterly report covers revenue, hiring plans and the roadmap for next year. ", 130))
			sc.Close()
			if HasInspectionLimit(got.Matches) {
				t.Fatal("residual caused refusal", expr, inbound)
			}
			if expr != `[0-9]+` && expr != `[0-9]{1,16}` && slices.Contains(matchNames(got.Matches), "Configured probe") {
				t.Fatal("residual caused finding", expr, inbound)
			}
		}
	}
}

func TestAdmissionDecoderOnlyReservation(t *testing.T) {
	views := make([]decodedResult, 9)
	for _, memo := range []*decodingMemo{nil, {}, {reassemblyPlan: reassemblyTestPlan(t), incomplete: true}} {
		memo.reassemblyObserveDecoded("ordinary", views)
		if memo != nil && (memo.reassemblySeen != nil || cap(memo.reassemblyPending) != 0) {
			t.Fatal("decoder-only consumer allocated graph")
		}
	}
}
