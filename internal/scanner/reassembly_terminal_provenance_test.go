// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyTerminalProvenance(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Marker", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	defer sc.Close()
	for _, enc := range reassemblyEncodings(strings.Repeat("x", 5000) + "MARK1234") {
		wantEncoding := enc.name
		if wantEncoding == "base64url" && !strings.ContainsAny(enc.text, "-_") {
			wantEncoding = encodingBase64
		}
		result := sc.ScanTextForDLP(t.Context(), reassemblyBang(enc.text))
		if !slices.ContainsFunc(result.Matches, func(m TextDLPMatch) bool {
			return m.PatternName == "Marker" && m.Encoded == wantEncoding && m.Span().Valid() && m.Span().ByteStart == 5000 && m.Span().ByteEnd == 5008 && strings.Contains(m.Span().ViewLabel, "reassembly:"+wantEncoding+":phase_0")
		}) {
			t.Errorf("%s: terminal provenance absent: %+v", enc.name, result)
		}
	}
}
