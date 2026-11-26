// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package receipttest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

func TestLegacyCorpusDirKeepsLegacyFilesInMixedFixture(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	files := map[string]string{
		"evidence-proxy-0.jsonl":            "legacy recorder",
		"evidence-proxy-0.receipt-v3.jsonl": "malformed profile claim",
		"evidence-proxy-1.jsonl":            evidencename.ReceiptProfilePrefix,
		"signer.pub":                        "fixture signer",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	projected := LegacyCorpusDir(t, dir)
	entries, err := os.ReadDir(projected)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("projected %d files, want 2", len(entries))
	}
	for _, name := range []string{"evidence-proxy-0.jsonl", "signer.pub"} {
		data, err := os.ReadFile(filepath.Clean(filepath.Join(projected, name)))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != files[name] {
			t.Fatalf("projected file %s differs from fixture", name)
		}
	}
}

func TestLegacyCorpusDirWithUnmixedFixtures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		file string
		keep bool
	}{
		{name: "legacy", file: "evidence-proxy-0.jsonl", keep: true},
		{name: "claimed", file: "evidence-proxy-0.receipt-v3.jsonl"},
		{name: "companion only", file: "signer.pub"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			want := ""
			if tc.keep {
				want = dir
			}
			if got := LegacyCorpusDir(t, dir); got != want {
				t.Fatalf("LegacyCorpusDir = %q, want %q", got, want)
			}
		})
	}
}
