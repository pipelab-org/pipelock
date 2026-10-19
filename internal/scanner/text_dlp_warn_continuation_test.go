// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestTextDLPWarnContinuation(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{
		{Name: "staged-key", Regex: `staged-[A-Za-z0-9]{10,}`, Severity: config.SeverityMedium, Action: config.ActionWarn},
		{Name: "enforced-key", Regex: `enforced-[A-Za-z0-9]{10,}`, Severity: config.SeverityHigh},
	}
	s := MustNew(cfg)
	defer s.Close()
	const staged = "staged-ABCDEFGHIJ1234"
	const enforced = "enforced-BBBBBBBBBB"
	splitHex := func(text string) string {
		encoded := hex.EncodeToString([]byte(text))
		return encoded[:20] + " " + encoded[20:]
	}
	for _, tc := range []struct {
		name, text string
		want       bool
		segments   bool
	}{
		{"split hex", splitHex(staged) + " separator " + splitHex(enforced), true, false},
		{"reversed split hex", splitHex(enforced) + " separator " + splitHex(staged), true, false},
		{"warn only", splitHex(staged), false, false},
		{"hex segments", hex.EncodeToString([]byte(staged)) + "/" + hex.EncodeToString([]byte(enforced)), true, true},
		{"base64 segments", base64.StdEncoding.EncodeToString([]byte(staged)) + "/" + base64.StdEncoding.EncodeToString([]byte(enforced)), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var matches []TextDLPMatch
			if tc.segments {
				matches = s.decodeTextSegmentsWithDecodes(tc.text, nil, textDLPAllPatterns)
			} else {
				matches = s.decodeSplitHexRunsWithDecodes(tc.text, nil, textDLPAllPatterns)
			}
			if hasEnforcedMatch(matches) != tc.want {
				t.Fatalf("decoded matches=%+v, want enforced=%v", matches, tc.want)
			}
			got := s.ScanTextForDLP(context.Background(), tc.text)
			found := slices.ContainsFunc(got.Matches, func(m TextDLPMatch) bool { return m.PatternName == "enforced-key" })
			if got.Clean == tc.want || found != tc.want {
				t.Fatalf("Clean=%v enforced=%v, want enforced=%v", got.Clean, found, tc.want)
			}
			if !tc.want && len(got.InformationalMatches) == 0 {
				t.Fatal("warn-only result lost informational matches")
			}
		})
	}
}
