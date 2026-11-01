// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestBrowserRoutePremise(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	// Preserve the reported limit to distinguish the original independent block.
	cfg.FetchProxy.Monitoring.MaxURLLength = 2048
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	for _, target := range []string{
		"https://mail.google.com/accounts/SetOSID?osidt=" + entropyTestMixed,
		"https://accounts.youtube.com/accounts/SetSID?sidt=" + entropyTestMixed,
		"https://mail.google.com/_/scs/mail-static/_/js/k=gmail.main.en." + entropyTestMixed + "/m=m_i",
	} {
		got := s.Scan(t.Context(), target)
		t.Logf("%s: allowed=%v scanner=%s reason=%s", target, got.Allowed, got.Scanner, got.Reason)
		if got.Allowed || got.Scanner != ScannerEntropy {
			t.Fatalf("expected entropy refusal: %+v", got)
		}
	}
	// Isolate the length failure from entropy in the same static route shape.
	base := "https://mail.google.com/_/scs/mail-static/_/js/"
	target := base + strings.Repeat("a", 2200-len(base))
	got := s.Scan(t.Context(), target)
	t.Logf("2200-byte static URL: allowed=%v scanner=%s reason=%s", got.Allowed, got.Scanner, got.Reason)
	if got.Allowed || got.Scanner != ScannerLength {
		t.Fatalf("expected legacy URL length refusal: %+v", got)
	}
}

func TestDefaultURLLengthFullScan(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	const base = "https://mail.google.com/_/scs/mail-static/_/js/"
	credential := "ghp_" + strings.Repeat("A", 36)
	for _, tc := range []struct {
		name, target, scanner string
	}{
		{"browser script", base + strings.Repeat("a", 2200-len(base)), ""},
		{"exact RFC limit", base + strings.Repeat("a", 8000-len(base)), ""},
		{"past RFC limit", base + strings.Repeat("a", 8001-len(base)), ScannerLength},
		{"octets rather than characters", base + strings.Repeat("é", 4000), ScannerLength},
		{"credential beyond old limit", base + strings.Repeat("a", 2200) + "/" + credential, ScannerCoreDLP},
		{"query credential beyond old limit", base + strings.Repeat("a", 2200) + "?osidt=" + credential, ScannerCoreDLP},
		{"credential at RFC limit", base + strings.Repeat("a", 8000-len(base)-1-len(credential)) + "/" + credential, ScannerCoreDLP},
		{"opaque path beyond old limit", base + strings.Repeat("a", 2200) + "/" + entropyTestMixed, ScannerEntropy},
		{"opaque query beyond old limit", base + strings.Repeat("a", 2200) + "?osidt=" + entropyTestMixed, ScannerEntropy},
		{"lookalike", "https://accounts.google.com.attacker.example/accounts/SetOSID?osidt=" + entropyTestMixed, ScannerEntropy},
		{"nonvendor", "https://auth.vendor.example/accounts/SetSID?sidt=" + entropyTestMixed, ScannerEntropy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Scan(t.Context(), tc.target)
			if got.Allowed != (tc.scanner == "") || (tc.scanner != "" && got.Scanner != tc.scanner) {
				t.Fatalf("%d bytes: %+v, want scanner %q", len(tc.target), got, tc.scanner)
			}
		})
	}
}
