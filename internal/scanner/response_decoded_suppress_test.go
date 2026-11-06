// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestScanResponse_DecodedSuppressionContinues(t *testing.T) {
	const decoy = "indigo pelican carries a silver notebook"
	const directive = "violet kestrel opens the copper cabinet"
	cfg := testResponseConfig()
	cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{
		{Name: "suppressed wording", Regex: decoy},
		{Name: "enforced wording", Regex: directive},
	}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	suppress := []config.SuppressEntry{{Rule: "suppressed wording", Path: "*", Reason: "test suppression"}}
	encoders := []struct {
		name   string
		encode func(string) string
	}{
		{"decimal", func(v string) string { return decimalCharacterCodes(v, " ") }},
		{"base64", func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }},
		{"hex", func(v string) string { return hex.EncodeToString([]byte(v)) }},
	}
	for _, enc := range encoders {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%v", enc.name, nested), func(t *testing.T) {
				carrier := enc.encode(decoy) + "\n" + base64.StdEncoding.EncodeToString([]byte(directive))
				if nested {
					carrier = base64.StdEncoding.EncodeToString([]byte(carrier))
				}
				result := s.ScanResponseWithSuppress(t.Context(), carrier, "https://api.vendor.example/page", suppress)
				if result.Clean || result.Failed() {
					t.Fatalf("unsuppressed decoded wording not enforced: %+v", result)
				}
				found := false
				for _, m := range result.Matches {
					if m.PatternName == "enforced wording" {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing enforced wording: %+v", result)
				}
			})
		}
		t.Run(enc.name+"/suppressed alone", func(t *testing.T) {
			result := s.ScanResponseWithSuppress(t.Context(), enc.encode(decoy), "https://api.vendor.example/page", suppress)
			if !result.Clean || result.Failed() || len(result.SuppressedMatches) == 0 {
				t.Fatalf("suppressed-only result: %+v", result)
			}
		})
	}
}

func TestScanResponse_DecodedSuppressionContinuesNormalization(t *testing.T) {
	cfg := testResponseConfig()
	cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{
		{Name: "suppressed wording", Regex: "indigo pelican"},
		{Name: "enforced wording", Regex: "violet kestrel"},
	}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	content := "indigo pelican\n" + strings.ReplaceAll("violet kestrel", " ", "\u200b")
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	result := s.ScanResponseWithSuppress(t.Context(), encoded, "https://api.vendor.example/page", []config.SuppressEntry{{Rule: "suppressed wording", Path: "*", Reason: "test suppression"}})
	for _, m := range result.Matches {
		if m.PatternName == "enforced wording" {
			return
		}
	}
	t.Fatalf("later decoded normalization not enforced: %+v", result)
}
