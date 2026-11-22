// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckLegacyEvidenceFormat(t *testing.T) {
	legacyOnly := t.TempDir()
	if err := os.WriteFile(filepath.Join(legacyOnly, "evidence-proxy-0.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	switched := t.TempDir()
	name := "11111111111111111111111111111111-0000000000000000.receipt-v3.jsonl"
	if err := os.WriteFile(filepath.Join(switched, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, dir string
		refused   bool
	}{
		{"legacy directory", legacyOnly, false},
		{"missing directory", filepath.Join(t.TempDir(), "missing"), false},
		{"directory switched to v3", switched, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkLegacyEvidenceFormat(tc.dir)
			if refused := err != nil && strings.Contains(err.Error(), "new evidence directory after a v3 switch"); refused != tc.refused {
				t.Fatalf("checkLegacyEvidenceFormat(%s) = %v, want refused %v", tc.name, err, tc.refused)
			}
			if !tc.refused && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestEvidenceWriterLockRefusesSwitchedDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "11111111111111111111111111111111-0000000000000000.receipt-v3.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := WithEvidenceWriterCeremonyLock(dir, func() error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("legacy write into a v3 directory: err=%v called=%v", err, called)
	}
}

func TestCheckLegacyEvidenceFormatRejectsFilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkLegacyEvidenceFormat(path); err == nil || !strings.Contains(err.Error(), "checking legacy evidence directory format") {
		t.Fatalf("legacy evidence file path: %v", err)
	}
}
