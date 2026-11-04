// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"

	scannerpkg "github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestKeepsDiagnosticPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		scanner string
		want    bool
	}{
		{scannerpkg.ScannerPathTraversal, true},
		{scannerpkg.ScannerCRLF, true},
		{scannerpkg.ScannerAllowlist, false},
		{scannerpkg.ScannerSSRF, false},
		{"dlp", false},
		{"", false},
	} {
		if got := KeepsDiagnosticPath(tc.scanner); got != tc.want {
			t.Errorf("KeepsDiagnosticPath(%q) = %v, want %v", tc.scanner, got, tc.want)
		}
	}
}
