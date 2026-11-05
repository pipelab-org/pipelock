// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadTrimmedFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	if err := os.WriteFile(p, []byte("  sk-trimmed-value\n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readTrimmedFile(p)
	if err != nil {
		t.Fatalf("readTrimmedFile: %v", err)
	}
	if got != "sk-trimmed-value" {
		t.Fatalf("readTrimmedFile = %q, want %q", got, "sk-trimmed-value")
	}
	got, err = readTrimmedFile("")
	if err != nil {
		t.Fatalf("readTrimmedFile(empty path): %v", err)
	}
	if got != "" {
		t.Fatalf("readTrimmedFile(empty path) = %q, want \"\"", got)
	}
	if _, err := readTrimmedFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("readTrimmedFile(missing) must fail closed")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrimmedFile(empty); err == nil {
		t.Fatal("readTrimmedFile(empty file) must fail closed")
	}
}

// TestModelKeyRedactedOnceInPlantedSecrets checks that a provider key added to
// the session's planted secrets is detected in agent chat output.
func TestModelKeyRedactedOnceInPlantedSecrets(t *testing.T) {
	modelKey := "sk-" + "live3a5c34b41316modelkeyvalue"
	planted := []string{"AKIA" + "IOSFODNN7EXAMPLE", modelKey}
	reply := "I read the key file. The value is " + modelKey + " for the provider."
	if !containsPlantedSecret(reply, planted) {
		t.Fatal("model key in the reply must be detected as a planted secret and redacted")
	}
	// A reply with no secret is untouched.
	if containsPlantedSecret("I could not reach the provider, request blocked.", planted) {
		t.Fatal("clean reply must not be flagged")
	}
}
