// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0
package proxy

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestProxy_ReloadConfiguredSeparatedPatterns(t *testing.T) {
	makeConfig := func(expr string) *config.Config {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.ScanEnv = false
		cfg.DLP.Patterns = []config.DLPPattern{{Name: "Configured record " + expr, Regex: expr, Severity: config.SeverityHigh}}
		return cfg
	}
	cfg := makeConfig(`[0-9]{16}`)
	initial := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), initial, metrics.New())
	if err != nil {
		initial.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { p.scannerPtr.Load().Close() })
	body := func(value string) string {
		enc := base64.StdEncoding.EncodeToString([]byte(value))
		var b strings.Builder
		b.WriteString(strings.Repeat("a!", 4200))
		for i := range len(enc) {
			b.WriteByte(enc[i])
			b.WriteByte('!')
		}
		return b.String()
	}
	digits := body("1234567812345678")
	letters := body(strings.Repeat("N", 16))
	for _, step := range []struct {
		name, expr    string
		digit, letter bool
	}{{"first load", `[0-9]{16}`, true, false}, {"changed", `[G-P]{16}`, false, true}, {"unchanged", `[G-P]{16}`, false, true}, {"restored", `[0-9]{16}`, true, false}} {
		t.Run(step.name, func(t *testing.T) {
			if step.name != "first load" {
				next := makeConfig(step.expr)
				if !p.Reload(next, scanner.MustNew(next)) {
					t.Fatal("reload refused")
				}
			}
			for _, tc := range []struct {
				text string
				want bool
			}{{digits, step.digit}, {letters, step.letter}} {
				result := p.scannerPtr.Load().ScanTextForDLP(t.Context(), tc.text)
				found := slices.ContainsFunc(result.Matches, func(m scanner.TextDLPMatch) bool { return m.PatternName == "Configured record "+step.expr })
				stale := slices.ContainsFunc(result.Matches, func(m scanner.TextDLPMatch) bool {
					return strings.HasPrefix(m.PatternName, "Configured record ") && m.PatternName != "Configured record "+step.expr
				})
				// Other alphabet phases can legitimately match the active grammar.
				// Rule identity, rather than a clear unrelated carrier, proves revocation.
				if tc.want && !found || stale || scanner.HasInspectionLimit(result.Matches) {
					t.Fatalf("configured reload: found=%v want=%v result=%+v", found, tc.want, result)
				}
			}
		})
	}
}
