// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

// Package testreceipt builds signed evidence fixtures for receipt reader tests.
package testreceipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

func V3(t *testing.T, dir string, damaged bool, actions ...v3.Action) (string, ed25519.PublicKey) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("receipt v3 writer fixtures require Linux directory locking")
	}
	key := v3FixtureKey()
	policyHash := v3.Digest([]byte("fixture policy"))
	writer, err := v3.OpenStreamWriter(t.Context(), v3.StreamWriterOptions{
		Dir: dir, SigningKey: key,
		Coverage: v3.Coverage{
			Surfaces: []string{"forward"}, ReceiptsRequired: true,
			RedactionRuleset: v3.Ruleset{Hash: v3.Digest([]byte("fixture rules")), ID: "example", Version: "1"},
		},
		Identity: v3.Writer{Product: "example", Version: "1", Instance: "fixture"}, PolicyHash: policyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close(t.Context(), nil) })
	for _, action := range actions {
		if err := writer.WriteAction(t.Context(), action, v3.CapturePolicy(policyHash)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.receipt-v3.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("v3 writer files %v: %v", files, err)
	}
	if damaged {
		if err := os.WriteFile(files[0], []byte("damaged first line\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return files[0], key.Public().(ed25519.PublicKey)
}

// EachV3 exercises an actual signed stream and damage that preserves its file name.
func EachV3(t *testing.T, check func(t *testing.T, dir, path string)) {
	t.Helper()
	for _, fixture := range []string{"signed", "damaged"} {
		t.Run(fixture, func(t *testing.T) {
			dir := t.TempDir()
			path, _ := V3(t, dir, fixture == "damaged")
			check(t, dir, path)
		})
	}
}

func RequiresV3Refusal(t *testing.T, err error, command, reader string) {
	t.Helper()
	want := command + ": receipt v3 evidence is not supported by " + reader + " in this release; use 'pipelock verify-receipt "
	if err == nil || (!strings.Contains(err.Error(), want+"<path>'") && !strings.Contains(err.Error(), want+"--chain <path>'")) {
		t.Fatalf("got %v, want %q", err, want)
	}
}

func v3FixtureKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("receipt reader test fixture"))
	return ed25519.NewKeyFromSeed(seed[:])
}
