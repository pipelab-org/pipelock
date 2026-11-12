// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

// A hex carrier shifted by one nibble reaches only the reassembly terminal.
// A key with one glued character must be found there as it is in plain text,
// and the prose and digit cases the plain-text rule keeps clean stay clean.
func TestReassemblyTerminalGluedBoundary(t *testing.T) {
	s := gluedBoundaryScanner(t)
	carrier := func(value string) string {
		return reassemblyBang("f" + hex.EncodeToString([]byte("!"+value)))
	}
	for _, tc := range gluedBoundaryCases() {
		t.Run(tc.name, func(t *testing.T) {
			body := carrier(tc.prefix + tc.secret)
			got := s.ScanTextForDLP(context.Background(), body)
			found := gluedBoundaryFound(got.Matches, got.InformationalMatches, tc.pattern)
			terminal := false
			for _, f := range reassemblyTerminal(s.reassemblyPlan, body, &assembledBudget{}).findings {
				terminal = terminal || f.PatternName == tc.pattern
			}
			if tc.want && (!found || !terminal) {
				t.Fatalf("shifted hex carrier missed %s: text DLP=%v terminal=%v", tc.pattern, found, terminal)
			}
			if !tc.want && (found || terminal) {
				t.Fatalf("shifted hex carrier flagged %s: text DLP=%v terminal=%v", tc.pattern, found, terminal)
			}
		})
	}
	for _, prose := range []string{
		"desk-ant-" + strings.Repeat("a", 20),
		"x" + "sk-ant-" + "report-final-version-2026-notes",
		"disk" + strings.Repeat("a1b2c3d4", 4),
		"9" + "4111" + strings.Repeat("1", 12),
	} {
		t.Run("clean/"+prose[:8], func(t *testing.T) {
			got := s.ScanTextForDLP(context.Background(), carrier(prose))
			if !got.Clean || len(got.InformationalMatches) != 0 {
				t.Fatalf("shifted hex prose produced a finding: %v %v", gluedMatchNames(got.Matches), gluedMatchNames(got.InformationalMatches))
			}
		})
	}
}
