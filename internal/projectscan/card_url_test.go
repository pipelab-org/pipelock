// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package projectscan

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestProjectScanCardURLs(t *testing.T) {
	patterns := mustCompileDLPPatterns(t)
	pan := cardtest.Issuer("4019", 16)
	for _, text := range []string{
		"https://api.vendor.example/path/" + pan[:4] + "." + pan[4:],
		"https://api.vendor.example/?a=" + pan[:8] + "&b=" + pan[8:],
	} {
		found := false
		for _, pattern := range patterns {
			found = found || pattern.name == patternCreditCard && pattern.matches(text)
		}
		if !found {
			t.Fatalf("URL card missing from project scan: %s", text)
		}
	}
}
