// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblySegmentsAndViews(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Configured suffix", re: regexp.MustCompile(`MARK.*NEVER`)}})
	if err != nil {
		t.Fatal(err)
	}
	failed := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("NEVER", maxReassembledTokenLen))))
	wire := reassemblyBang(hex.EncodeToString([]byte("MARK NEVER")))
	needle := reassemblyBang(hex.EncodeToString([]byte("NEVER")))
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Configured suffix", Regex: `MARK.*NEVER`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	defer sc.Close()
	for _, delta := range []int{-1, 0, 1} {
		pad := maxReassembledTokenLen - len(wire) + len(needle)/2 + delta
		body := strings.Repeat("!", pad) + wire
		cueStart := pad + len(wire) - len(needle)
		cueEnd := len(body)
		if cueStart >= maxReassembledTokenLen || cueEnd <= maxReassembledTokenLen {
			t.Fatal("cue does not cross segment limit")
		}
		budget := &assembledBudget{}
		first := reassemblyTerminal(p, failed, budget)
		second := reassemblyTerminal(p, body, budget)
		if len(first.findings) != 0 || first.incomplete || len(second.findings) == 0 || second.incomplete {
			t.Fatalf("direct different views delta=%d first=%+v second=%+v", delta, first, second)
		}
		ctx, release := WithSharedDecodes(context.Background())
		a := sc.ScanTextForDLP(ctx, failed)
		b := sc.ScanTextForDLP(ctx, body)
		release()
		if !a.Clean || b.Clean || HasInspectionLimit(a.Matches) || HasInspectionLimit(b.Matches) {
			t.Fatalf("public shared views delta=%d first=%+v second=%+v", delta, a, b)
		}
		t.Logf("SEGMENT_VIEW delta=%d cue=[%d,%d) segment_limit=%d shared_budget_found=true public_found=true", delta, cueStart, cueEnd, maxReassembledTokenLen)
	}
}

func TestReassemblyActualSegments(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Configured suffix", re: regexp.MustCompile(`MARK.*NEVER`)}})
	if err != nil {
		t.Fatal(err)
	}
	wire := hex.EncodeToString([]byte("MARK NEVER"))
	needle := hex.EncodeToString([]byte("NEVER"))
	cut := len(wire) - len(needle)/2
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Configured suffix", Regex: `MARK.*NEVER`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	defer sc.Close()
	for _, delimiter := range []string{"/", ":", ","} {
		body := wire[:cut] + delimiter + wire[cut:]
		pieces := textDLPSegments(body)
		if len(pieces) != 2 || strings.Contains(pieces[0], needle) || strings.Contains(pieces[1], needle) {
			t.Fatal("required cue did not cross actual segmentation")
		}
		budget := &assembledBudget{}
		ctx, release := WithSharedDecodes(context.Background())
		for _, piece := range pieces {
			r := reassemblyTerminal(p, piece, budget)
			if len(r.findings) != 0 || r.incomplete {
				t.Fatalf("individual segment unexpectedly matched: %+v", r)
			}
			if got := sc.ScanTextForDLP(ctx, piece); !got.Clean || HasInspectionLimit(got.Matches) {
				t.Fatalf("individual public segment unexpectedly matched: %+v", got)
			}
		}
		joined := reassemblyTerminal(p, body, budget)
		public := sc.ScanTextForDLP(ctx, body)
		release()
		if len(joined.findings) == 0 || joined.incomplete || public.Clean || HasInspectionLimit(public.Matches) {
			t.Fatalf("combined segment cue lost: direct=%+v public=%+v", joined, public)
		}
		t.Logf("ACTUAL_SEGMENTS delimiter=%q pieces=%v individual_matches=0 combined_terminal_found=true combined_public_found=true", delimiter, pieces)
	}
}
