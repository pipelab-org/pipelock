// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func reassemblyMarkerPlan(t *testing.T) *reassemblyPlan {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Marker", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc.reassemblyPlan
}

func TestReassemblyScanAllowance(t *testing.T) {
	p := reassemblyMarkerPlan(t)
	for _, inbound := range []bool{false, true} {
		t.Run(fmt.Sprint(inbound), func(t *testing.T) {
			var memos []*decodingMemo
			for i := range 2 {
				m := &decodingMemo{reassemblyPlan: p, reassemblyDeferred: true, reassemblyInbound: inbound, assembledBytes: 0}
				if i == 0 {
					m.assembledBytes = maxDecodeTotalBytes - 12
				}
				defer m.releaseProjection()
				m.reassemblyObserve(reassemblyBang(fmt.Sprintf("4d41524b3132333%d", i)))
				memos = append(memos, m)
			}
			r := finishAssembled(TextDLPResult{Clean: true}, memos...)
			partial := false
			for _, match := range r.Matches {
				partial = partial || match.PatternName == PartialEncodedContentPattern
			}
			if inbound {
				if !partial || HasInspectionLimit(r.Matches) {
					t.Fatalf("inbound allowance result: %+v", r)
				}
			} else if !HasInspectionLimit(r.Matches) {
				t.Fatalf("separate terminal allowances: %+v", r)
			}
			if memos[1].assembledBytes > maxDecodeTotalBytes {
				t.Fatalf("allowance exceeded: %d", memos[1].assembledBytes)
			}
			t.Logf("used=%d limit=%d refusal=%v partial=%v", memos[1].assembledBytes, maxDecodeTotalBytes, HasInspectionLimit(r.Matches), partial)
		})
	}
}

func TestReassemblyIdenticalLaneCharges(t *testing.T) {
	b := &assembledBudget{}
	a, c := b.chargesFor("4d!41!52!4b"), b.chargesFor("4d 41 52 4b")
	for offset := range 4 {
		if !b.charge(a, 0, 0, offset) || !b.charge(c, 0, 0, offset) {
			t.Fatal("identical lane refused")
		}
	}
	if b.used != 4 {
		t.Fatalf("identical lane charged %d bytes, want 4", b.used)
	}
}
