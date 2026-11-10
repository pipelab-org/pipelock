// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func reassemblyAnchoredCarrier(escape string, tail int) string {
	const mark = "MARK1234"
	var encoded strings.Builder
	for i := 0; i < len(mark); i++ {
		if escape == "html" {
			fmt.Fprintf(&encoded, "&#%d;", mark[i])
		} else {
			fmt.Fprintf(&encoded, `\u%04x`, mark[i])
		}
	}
	encoded.WriteString(strings.Repeat(".", tail))
	return reassemblyBang(hex.EncodeToString([]byte(encoded.String())))
}

func reassemblyAnchoredScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{
		Name: "Anchored mark", Regex: `^MARK[0-9]{4}`, Severity: config.SeverityHigh, Keywords: []string{"lookup"},
	}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func reassemblyAnchoredFound(result TextDLPResult) bool {
	for _, match := range result.Matches {
		if match.PatternName == "Anchored mark" {
			return true
		}
	}
	return false
}

func TestReassemblyAnchoredKeywordAfterUnqualifiedDuplicate(t *testing.T) {
	sc := reassemblyAnchoredScanner(t)
	gap := strings.Repeat(" ", 4)
	for _, escape := range []string{"html", "json"} {
		t.Run(escape, func(t *testing.T) {
			long := reassemblyAnchoredCarrier(escape, 5000)
			short := reassemblyAnchoredCarrier(escape, 0)
			qualified := "lookup " + long
			if result := sc.ScanTextForDLP(t.Context(), qualified); !reassemblyAnchoredFound(result) || result.Incomplete || HasInspectionLimit(result.Matches) {
				t.Fatalf("qualified carrier missed: %+v", result)
			}
			both := "zzzz " + long + gap + "lookup " + long
			if result := sc.ScanTextForDLP(t.Context(), both); !reassemblyAnchoredFound(result) || result.Incomplete || HasInspectionLimit(result.Matches) {
				t.Fatalf("qualified duplicate hidden by earlier carrier: %+v", result)
			}
			shortBoth := "zzzz " + short + gap + "lookup " + short
			if result := sc.ScanTextForDLP(t.Context(), shortBoth); !reassemblyAnchoredFound(result) || result.Incomplete {
				t.Fatalf("short qualified duplicate missed: %+v", result)
			}
			unqualified := "zzzz " + long + gap + "other " + long
			if result := sc.ScanTextForDLP(t.Context(), unqualified); reassemblyAnchoredFound(result) || result.Incomplete || HasInspectionLimit(result.Matches) {
				t.Fatalf("unqualified carriers were not clean: %+v", result)
			}
		})
	}
}
