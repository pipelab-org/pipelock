// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

func TestReceiptRecoveryChecksLockAndPreservesEvidence(t *testing.T) {
	dir := t.TempDir()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	writer, err := v3.OpenStreamWriter(t.Context(), v3.StreamWriterOptions{
		Dir: dir, SigningKey: key, Identity: v3.Writer{Instance: "example", Product: "Pipelock", Version: "3"},
		PolicyHash: v3.Digest(nil),
		Coverage:   v3.Coverage{RedactionRuleset: v3.Ruleset{ID: "example", Version: "1", Hash: v3.Digest(nil)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close(t.Context(), nil) })
	run := func(pinned string) (string, error) {
		var out bytes.Buffer
		cmd := receiptRecoveryCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{dir, "--key", pinned})
		err := cmd.ExecuteContext(t.Context())
		return out.String(), err
	}
	pin := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if _, err := run(pin); err == nil || !strings.Contains(err.Error(), "still in use") {
		t.Fatalf("live writer was not reported, got %v", err)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.receipt-v3.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("want one evidence stream, got %v (%v)", files, err)
	}
	before, err := os.ReadFile(filepath.Clean(files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := run(pin); err != nil || !strings.Contains(output, "\"verdict\":\"VALID\"") {
		t.Fatalf("valid history was refused: %v\n%s", err, output)
	}
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 1
	other := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if output, err := run(hex.EncodeToString(other)); err == nil || !strings.Contains(err.Error(), "configure prior signer key") ||
		!strings.Contains(output, "\"verdict\":\"INVALID\"") {
		t.Fatalf("untrusted history did not name its needed key: %v\n%s", err, output)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("startup inspection changed inventory: %v (%v)", entries, err)
	}
	after, err := os.ReadFile(filepath.Clean(files[0]))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("startup inspection changed evidence: %v", err)
	}
}

func TestReceiptRecoveryReportsNoEvidence(t *testing.T) {
	dir := t.TempDir()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	var out bytes.Buffer
	cmd := receiptRecoveryCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{dir, "--key", hex.EncodeToString(key.Public().(ed25519.PublicKey))})
	err := cmd.ExecuteContext(t.Context())
	if err == nil || !strings.Contains(err.Error(), "NO_EVIDENCE") ||
		!strings.Contains(err.Error(), "supply the directory containing the v3 receipt files") ||
		!strings.Contains(out.String(), "\"verdict\":\"INCOMPLETE\"") {
		t.Fatalf("empty history did not report incomplete evidence: %v\n%s", err, &out)
	}
}
