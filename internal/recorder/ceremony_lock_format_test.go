// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
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

// TestCheckLegacyEvidenceFormatClaimsByNameAndContent holds the recorder to the
// v3 claim rule: any receipt profile name, a malformed profile name, and v3
// content under a legacy candidate name all mean the directory belongs to a v3
// reader, so a legacy write must be refused.
func TestCheckLegacyEvidenceFormatClaimsByNameAndContent(t *testing.T) {
	v3Line := `{"payloadType":"application/vnd.pipelock.receipt.v3+json","payload":"e30="}` + "\n"
	legacyLine := `{"v":1,"type":"action_receipt"}` + "\n"
	for _, tc := range []struct {
		name    string
		files   map[string]string
		refused bool
	}{
		{"future profile name", map[string]string{"11111111111111111111111111111111-0000000000000000.receipt-v4.jsonl": ""}, true},
		{"malformed v3 name", map[string]string{"stream.receipt-v3.jsonl": ""}, true},
		{"v3 content under recorder shard name", map[string]string{"evidence-proxy-0.jsonl": v3Line}, true},
		{"v3 content under group artifact name", map[string]string{"receipt-group-a.json": v3Line}, true},
		{"v3 content under activation name", map[string]string{"activation-receipts.jsonl": v3Line}, true},
		{"legacy content under recorder shard name", map[string]string{"evidence-proxy-0.jsonl": legacyLine}, false},
		{"v3 content under unrelated name", map[string]string{"notes.txt": v3Line}, false},
		{"profile name only as a prefix", map[string]string{"x.receipt-v3.jsonl.bak": ""}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, data := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := checkLegacyEvidenceFormat(dir)
			if tc.refused != errors.Is(err, ErrLegacyEvidenceFormat) {
				t.Fatalf("checkLegacyEvidenceFormat = %v, want refused %v", err, tc.refused)
			}
			if !tc.refused && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestCheckLegacyEvidenceFormatRefusesUnreadableCandidate holds the fail-closed
// direction: a legacy candidate the recorder cannot read leaves the directory
// unclassified, so the write is refused instead of assumed to be legacy.
func TestCheckLegacyEvidenceFormatRefusesUnreadableCandidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence-proxy-0.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if f, err := os.Open(path); err == nil {
		_ = f.Close()
		t.Skip("file permissions do not restrict this user")
	}
	err := checkLegacyEvidenceFormat(dir)
	if err == nil || errors.Is(err, ErrLegacyEvidenceFormat) {
		t.Fatalf("checkLegacyEvidenceFormat on an unreadable candidate = %v, want a read error", err)
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
