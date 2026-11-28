// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
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
			if refused := errors.Is(err, ErrLegacyEvidenceFormat); refused != tc.refused {
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
	if f, err := os.Open(filepath.Clean(path)); err == nil {
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

func TestDiscoverRenamedReceiptContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), []byte(evidencename.ReceiptProfilePrefix+"v3\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DiscoverEvidenceLocations(dir); !errors.Is(err, ErrLegacyEvidenceFormat) {
		t.Fatalf("default discovery error = %v, want receipt refusal", err)
	}
	if _, err := DiscoverEvidenceLocations(dir, MixedReceiptProfiles); err != nil {
		t.Fatalf("mixed discovery error = %v", err)
	}
}

func TestReceiptNamedFileWithDotSuffix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stream.receipt-v3.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path += string(filepath.Separator) + "."
	if _, err := ReadEntries(path); !errors.Is(err, ErrLegacyEvidenceFormat) {
		t.Errorf("ReadEntries error = %v", err)
	}
	if err := WalkEntries(path, func(Entry) error { return nil }); !errors.Is(err, ErrLegacyEvidenceFormat) {
		t.Errorf("WalkEntries error = %v", err)
	}
	file, _, err := openRegularEvidenceFile(path, nil)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, ErrLegacyEvidenceFormat) {
		t.Errorf("openRegularEvidenceFile error = %v", err)
	}
}

func TestBoundedInventoryChecksRemainingReceiptContent(t *testing.T) {
	dir := t.TempDir()
	for i := range 10 {
		path := filepath.Join(dir, fmt.Sprintf("evidence-proxy-%d.jsonl", i))
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	handle, err := os.Open(filepath.Clean(dir))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := handle.ReadDir(-1)
	_ = handle.Close()
	if err != nil || len(entries) < 3 {
		t.Fatalf("directory entries = %d, error = %v", len(entries), err)
	}
	path := filepath.Join(dir, entries[len(entries)-1].Name())
	if err := os.WriteFile(path, []byte(evidencename.ReceiptProfilePrefix+"v3\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	location := EvidenceLocation{Root: dir, Dir: dir}
	if _, _, err := ReadEvidenceLocationEntriesBounded(location, 1); !errors.Is(err, ErrLegacyEvidenceFormat) {
		t.Fatalf("bounded inventory error = %v, want receipt refusal", err)
	}
}

func TestRefuseReceiptDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := RefuseReceiptDirectory(dir); err != nil {
		t.Fatalf("empty directory: %v", err)
	}
	if err := RefuseReceiptDirectory(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing directory accepted")
	}
	path := filepath.Join(dir, "stream.receipt-v3.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RefuseReceiptDirectory(dir); err == nil || !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("profile directory: %v", err)
	}
	if err := RefuseReceiptDirectory(dir, MixedReceiptProfiles); err != nil {
		t.Fatalf("mixed mode: %v", err)
	}
}

func TestReadLegacyDirectoryBounded(t *testing.T) {
	write := func(t *testing.T, dir string, names ...string) {
		t.Helper()
		for _, name := range names {
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("within budget", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "evidence-a-0.jsonl", "evidence-b-0.jsonl")
		entries, err := ReadLegacyDirectoryBounded(dir, 3)
		if err != nil || len(entries) != 2 {
			t.Fatalf("entries=%d err=%v", len(entries), err)
		}
	})
	t.Run("exactly at budget", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "evidence-a-0.jsonl", "evidence-b-0.jsonl")
		if entries, err := ReadLegacyDirectoryBounded(dir, 2); err != nil || len(entries) != 2 {
			t.Fatalf("entries=%d err=%v", len(entries), err)
		}
	})
	t.Run("over budget fails closed", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "evidence-a-0.jsonl", "evidence-b-0.jsonl", "evidence-c-0.jsonl")
		entries, err := ReadLegacyDirectoryBounded(dir, 2)
		if !errors.Is(err, ErrEvidenceReadLimitExceeded) || entries != nil {
			t.Fatalf("entries=%v err=%v, want read-limit refusal", entries, err)
		}
	})
	t.Run("receipt profile refused", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "evidence-a-0.jsonl", "stream.receipt-v3.jsonl")
		if _, err := ReadLegacyDirectoryBounded(dir, 10); !errors.Is(err, ErrLegacyEvidenceFormat) {
			t.Fatalf("err=%v, want receipt-profile refusal", err)
		}
	})
	t.Run("missing directory", func(t *testing.T) {
		if _, err := ReadLegacyDirectoryBounded(filepath.Join(t.TempDir(), "missing"), 2); err == nil {
			t.Fatal("missing directory accepted")
		}
	})
}
