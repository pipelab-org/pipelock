// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/gitprotect"
)

func TestScanDiffInlineCoreFloor(t *testing.T) {
	for _, marker := range []string{"# pipelock:ignore", "// pipelock:ignore aws access id"} {
		t.Run(marker, func(t *testing.T) {
			// Keep an on-disk marker too: both diff and source suppression must retain the finding.
			file := filepath.Join(t.TempDir(), "fixture.txt")
			line := "value=" + fakeKey() + " " + marker + "\n"
			if err := os.WriteFile(file, []byte(line), 0o600); err != nil {
				t.Fatal(err)
			}
			diff := "diff --git a/fixture b/fixture\n--- a/fixture\n+++ " + file + "\n@@ -0,0 +1 @@\n+" + line
			stdin, err := os.CreateTemp(t.TempDir(), "stdin")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stdin.Close() }()
			if _, err = stdin.WriteString(diff); err != nil {
				t.Fatal(err)
			}
			if _, err = stdin.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			old := os.Stdin
			os.Stdin = stdin
			t.Cleanup(func() { os.Stdin = old })
			cmd := testRootCmd()
			cmd.SetArgs([]string{"git", "scan-diff", "--json", "--verbose"})
			var out, diagnostics bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&diagnostics)
			if err := cmd.Execute(); !errors.Is(err, ErrSecretsFound) {
				t.Fatalf("got %v, want ErrSecretsFound (exit 1); output=%s", err, out.String())
			}
			var findings []gitprotect.Finding
			if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].Pattern != "AWS Access ID" {
				t.Fatalf("unexpected findings: %+v", findings)
			}
			if strings.Contains(out.String(), fakeKey()) || strings.Contains(diagnostics.String(), "SUPPRESSED") {
				t.Fatalf("secret or suppressed core finding in output: %s %s", out.String(), diagnostics.String())
			}
			if !strings.Contains(diagnostics.String(), "KEPT:") || !strings.Contains(diagnostics.String(), "core floor patterns cannot be suppressed") {
				t.Fatalf("missing core floor diagnostic: %s", diagnostics.String())
			}
		})
	}
}

// TestScanDiffAppliesCoreOnlyFloor: scan-diff applies core floor patterns that
// are not in the configured pattern list, as the proxy scanner does.
func TestScanDiffAppliesCoreOnlyFloor(t *testing.T) {
	diff := "diff --git a/k.json b/k.json\n--- a/k.json\n+++ b/k.json\n@@ -0,0 +1 @@\n+{\"type\": \"service_" + "account\"}\n"
	stdin, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	if _, err = stdin.WriteString(diff); err != nil {
		t.Fatal(err)
	}
	if _, err = stdin.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin = old })
	cmd := testRootCmd()
	cmd.SetArgs([]string{"git", "scan-diff", "--json"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); !errors.Is(err, ErrSecretsFound) {
		t.Fatalf("got %v, want ErrSecretsFound; output=%s", err, out.String())
	}
	var findings []gitprotect.Finding
	if err := json.Unmarshal(out.Bytes(), &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Pattern != "GCP Service Account Key" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}
