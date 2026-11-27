// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

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
