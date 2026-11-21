// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDirectory(t *testing.T) {
	const v3File = "11111111111111111111111111111111-0000000000000000.receipt-v3.jsonl"
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "sdk", "conformance", "testdata", "v3", "g01-valid-line", v3File))
	if err != nil {
		t.Fatal(err)
	}
	// A root holding v3 receipts is verified whole, even when a
	// subdirectory also holds recorder evidence.
	mixed := t.TempDir()
	if err := os.WriteFile(filepath.Join(mixed, v3File), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mixed, "operational"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mixed, "operational", "evidence-example-0.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A legacy-only root resolves to its single recorder location.
	legacy := t.TempDir()
	if err := os.Mkdir(filepath.Join(legacy, "operational"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "operational", "evidence-example-0.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	mixedAbs, err := filepath.Abs(mixed)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, dir, location, want, wantErr string
	}{
		{name: "v3 root", dir: mixed, want: mixedAbs},
		{name: "legacy location", dir: legacy, want: filepath.Join(legacy, "operational")},
		{name: "explicit location skips the v3 root", dir: mixed, location: "missing", wantErr: "missing"},
		{name: "missing directory", dir: filepath.Join(t.TempDir(), "missing"), wantErr: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveDirectory(tc.dir, tc.location)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ResolveDirectory error = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want, _ := filepath.EvalSymlinks(tc.want)
			gotReal, _ := filepath.EvalSymlinks(got)
			if gotReal != want {
				t.Fatalf("ResolveDirectory = %q, want %q", got, tc.want)
			}
		})
	}
}
