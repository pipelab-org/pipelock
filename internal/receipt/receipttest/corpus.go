// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

// Package receipttest provides fixtures for legacy receipt parity tests.
package receipttest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

// LegacyCorpusDir returns a directory with legacy recorder shards and their
// companion files. Mixed fixtures are copied without claimed receipt-profile
// files. A directory with no legacy shards returns an empty path.
func LegacyCorpusDir(t testing.TB, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var legacyShard bool
	excluded := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		shard := strings.HasPrefix(name, "evidence-")
		_, profile := evidencename.ReceiptProfileVersion(name)
		if profile || shard && hasProfileEnvelope(t, filepath.Join(dir, name)) {
			excluded[name] = true
			continue
		}
		legacyShard = legacyShard || shard
	}
	if !legacyShard {
		return ""
	}
	if len(excluded) == 0 {
		return dir
	}
	dst, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || excluded[name] {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func hasProfileEnvelope(t testing.TB, path string) bool {
	t.Helper()
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	claimed, err := evidencename.ProbeReceiptContent(file)
	if err != nil {
		t.Fatal(err)
	}
	return claimed
}
