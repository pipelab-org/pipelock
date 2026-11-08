// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyProviderIdentity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	defer sc.Close()
	value := "sk-proj-" + strings.Repeat("a", 24)
	input := "!" + value
	body := reassemblyBang(hex.EncodeToString([]byte(input)))
	production := sc.ScanTextForDLP(t.Context(), body)
	count := 0
	for _, match := range production.Matches {
		if match.PatternName == "OpenAI API Key" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("provider value produced %d findings", count)
	}
	result := reassemblyTerminal(sc.reassemblyPlan, body, &assembledBudget{})
	target := sha256.Sum256([]byte(value))
	for _, match := range result.findings {
		if match.PatternName == "OpenAI API Key" {
			if !match.hasValueIdentity || match.valueIdentity != target {
				t.Fatalf("provider delimiter entered identity: %+v", match)
			}
			return
		}
	}
	t.Fatal("provider key not detected")
}
