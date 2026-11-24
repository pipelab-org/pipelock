// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package gitprotect

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestScanDiffCardURLs(t *testing.T) {
	patterns := CompileDLPPatterns(config.Defaults().DLP.Patterns)
	pan := cardtest.Issuer("4019", 16)
	for _, text := range []string{
		"https://api.vendor.example/path/" + pan[:4] + "." + pan[4:],
		"https://api.vendor.example/?a=" + pan[:8] + "&b=" + pan[8:],
		"https://v2.vendor.example:443/?a1=" + pan[:8] + "&b2=" + pan[8:],
	} {
		diff := "diff --git a/pay.txt b/pay.txt\n--- a/pay.txt\n+++ b/pay.txt\n@@ -0,0 +1 @@\n+" + text + "\n"
		result, err := ScanDiff(diff, patterns)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, finding := range result.Findings {
			found = found || finding.Pattern == "Credit Card Number"
			if strings.Contains(finding.Content, pan[:4]) || strings.Contains(finding.Content, pan[4:]) {
				t.Fatalf("card bytes retained in diff report: %s", finding.Content)
			}
		}
		if !found {
			t.Fatalf("URL card missing from diff: %s", text)
		}
	}
}

func TestScanDiffCardRedactionUnion(t *testing.T) {
	patterns := CompileDLPPatterns(config.Defaults().DLP.Patterns)
	pan := cardtest.Issuer("4019", 16)
	invalid := pan[:15] + string('0'+(pan[15]-'0'+1)%10)
	public := strings.Repeat("4242", 4)
	text := pan + " " + invalid + " " + public
	diff := "diff --git a/pay.txt b/pay.txt\n--- a/pay.txt\n+++ b/pay.txt\n@@ -0,0 +1 @@\n+" + text + "\n"
	got, err := ScanDiff(diff, patterns)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) == 0 {
		t.Fatal("card finding missing")
	}
	for _, f := range got.Findings {
		if strings.Contains(f.Content, pan) || strings.Contains(f.Content, invalid) || !strings.Contains(f.Content, public) {
			t.Fatalf("redaction union: %q", f.Content)
		}
	}
}
