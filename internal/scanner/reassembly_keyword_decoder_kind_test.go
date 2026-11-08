// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// A keyword-gated rule elsewhere in the configuration must not change which
// decoded views the terminal treats as text.
func TestReassemblyKeywordModeKeepsDecoderPolicy(t *testing.T) {
	carrier := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5000) + "MARK1234")))
	for _, keywordMode := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.ScanEnv = false
		cfg.DLP.Patterns = []config.DLPPattern{{Name: "Shape", Regex: `[A-Z]{4}[0-9]{4}`, Severity: config.SeverityHigh}}
		if keywordMode {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Other", Regex: `ZQ[0-9]{12}`, Severity: config.SeverityHigh, Keywords: []string{"lookup"}})
		}
		sc := MustNew(cfg)
		for _, inbound := range []bool{false, true} {
			t.Run(fmt.Sprintf("keywords=%v/inbound=%v", keywordMode, inbound), func(t *testing.T) {
				ctx := t.Context()
				if inbound {
					ctx = WithInboundDirection(ctx)
				}
				if r := sc.ScanTextForDLP(ctx, carrier); !slices.Contains(matchNames(r.Matches), "Shape") {
					t.Fatalf("text carrier lost: %+v", r)
				}
				r := sc.ScanTextForDLP(ctx, base64.StdEncoding.EncodeToString([]byte(carrier)))
				if !r.Clean || len(r.Matches) != 0 {
					t.Fatalf("decoder-only shape enforced: %+v", r)
				}
			})
		}
		sc.Close()
	}
}
