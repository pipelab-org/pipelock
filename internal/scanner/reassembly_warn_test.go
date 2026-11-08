// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyWarnDelivery(t *testing.T) {
	for _, defaults := range []bool{false, true} {
		for _, quiet := range []bool{false, true} {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			cfg.DLP.IncludeDefaults = &defaults
			cfg.DLP.Patterns = []config.DLPPattern{{Name: "Warn record", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh, Action: config.ActionWarn}}
			sc := MustNew(cfg)
			warned := 0
			sc.SetDLPWarnHook(func(_ context.Context, name, _ string) {
				if name == "Warn record" {
					warned++
				}
			})
			body := strings.Repeat("!", maxReassembledTokenLen+1) + reassemblyBang(reassemblyEncodings("MARK1234")[0].text)
			for round := range 2 {
				var result TextDLPResult
				if quiet {
					result = sc.ScanTextForDLPQuiet(t.Context(), body)
				} else {
					result = sc.ScanTextForDLP(t.Context(), body)
				}
				if !result.Clean || len(result.Matches) != 0 || len(result.InformationalMatches) != 1 || result.InformationalMatches[0].PatternName != "Warn record" {
					t.Fatal("terminal warning enforced, duplicated or lost", defaults, quiet, result)
				}
				want := round + 1
				if quiet {
					want = 0
				}
				if warned != want {
					t.Fatal("warn hook count", warned, want)
				}
			}
			sc.Close()
		}
	}
}
