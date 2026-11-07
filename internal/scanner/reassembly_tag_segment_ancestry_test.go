// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyTagSegmentAncestry(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Shape probe", Regex: `[0-9]{16}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	defer sc.Close()
	encoded := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5000) + strings.Repeat("3", 16))))
	plain := sc.ScanTextForDLP(t.Context(), encoded)
	if !slices.Contains(matchNames(plain.Matches), "Shape probe") || HasInspectionLimit(plain.Matches) {
		t.Fatalf("textual positive lost coverage: %+v", plain)
	}
	body := "visible prefix " + unicodeTags(encoded) + " visible suffix"
	result := sc.ScanTextForDLP(t.Context(), body)
	if slices.Contains(matchNames(result.Matches), "Shape probe") || HasInspectionLimit(result.Matches) {
		t.Fatalf("decoder descendant gained textual eligibility: %+v", result)
	}
}
