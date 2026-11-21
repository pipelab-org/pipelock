// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainMixedDirectoryVerifiesRoot(t *testing.T) {
	fixtures := os.DirFS(filepath.Join("..", "..", "sdk", "conformance", "testdata", "v3", "g09-rotation-match"))
	dir := t.TempDir()
	files, err := fs.ReadDir(fixtures, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		name := file.Name()
		if !strings.HasSuffix(name, ".jsonl") && !strings.HasPrefix(name, "receipt-v3-cutover-") {
			continue
		}
		data, err := fs.ReadFile(fixtures, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A subdirectory with recorder evidence must not narrow verification
	// away from the v3 streams and legacy chains at the root.
	operational := filepath.Join(dir, "operational")
	if err := os.Mkdir(operational, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(operational, "evidence-example-0.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	requestBytes, err := fs.ReadFile(fixtures, "request.json")
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(requestBytes, &request); err != nil {
		t.Fatal(err)
	}
	args := []string{"chain", "--dir", "--allow-prefix"}
	for _, key := range request.Keys {
		args = append(args, "--key", key)
	}
	stdout, stderr, code := runRoot(t, append(args, dir)...)
	if code != 0 || !strings.Contains(stdout, "VALID PREFIX, END UNPROVEN") {
		t.Fatalf("mixed directory: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
}

func TestChainLegacySelectionScopesBindingsToSession(t *testing.T) {
	const contract = "sha256:" + "aa"
	for _, tc := range []struct {
		name        string
		opts        chainOptions
		wantSession string
		wantBinding bool
	}{
		{"no selection", chainOptions{sessionID: "proxy"}, "", false},
		{"explicit session", chainOptions{sessionID: "run-a", sessionExplicit: true}, "run-a", false},
		{"bindings use default session", chainOptions{sessionID: "proxy", evidenceBindingOptions: evidenceBindingOptions{expectContractHash: contract}}, "proxy", true},
		{"bindings keep explicit session", chainOptions{sessionID: "run-b", sessionExplicit: true, evidenceBindingOptions: evidenceBindingOptions{expectContractHash: contract}}, "run-b", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.opts.legacySelection()
			if err != nil {
				t.Fatal(err)
			}
			if got.Session != tc.wantSession || (got.Bindings != nil) != tc.wantBinding {
				t.Fatalf("selection = session %q bindings %v, want session %q bindings %v", got.Session, got.Bindings != nil, tc.wantSession, tc.wantBinding)
			}
			if got.Bindings != nil && got.Bindings.ExpectHeadHash != "" {
				t.Fatal("legacy bindings must not carry the v3 head expectation")
			}
		})
	}
}
