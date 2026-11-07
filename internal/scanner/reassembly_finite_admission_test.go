// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyFiniteValidatedAdmission(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = nil
	for _, p := range config.DefaultDLPPatterns() {
		switch p.Name {
		case "Bitcoin WIF Private Key", "IBAN", "Credit Card Number":
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, p)
		}
	}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, plain := range []string{strings.Repeat("5", 512), strings.Repeat("GB00"+strings.Repeat("A", 18)+"!", 32)} {
		body := reassemblyBang(base64.StdEncoding.EncodeToString([]byte(plain)))
		budget := &assembledBudget{used: maxDecodeTotalBytes}
		result := assembledLayer(sc.reassemblyPlan, body, budget, 0)
		if result.incomplete || len(result.findings) != 0 || budget.used != maxDecodeTotalBytes {
			t.Fatalf("rejected candidates admitted a lane: %+v used=%d", result, budget.used)
		}
	}
	for _, plain := range []string{
		"5HueCGU8rMjx" + "EXxiPuD5BDku4MkFqe" + "Zyd4dZ1jvhTVqvbTLvyTJ",
		"GB82" + "WEST12345698765432",
	} {
		body := reassemblyBang(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 128) + "!" + plain + "!" + strings.Repeat("x", 128))))
		result := assembledLayer(sc.reassemblyPlan, body, &assembledBudget{}, 0)
		if result.incomplete || len(result.findings) == 0 {
			t.Fatalf("validated candidate lost admission: %+v", result)
		}
	}
}
