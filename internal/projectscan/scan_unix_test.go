// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package projectscan

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestScanFiles_SymlinkTargetsAreInspectedByTarget(t *testing.T) {
	outside := t.TempDir()
	big := filepath.Join(outside, "big")
	if err := os.WriteFile(big, make([]byte, maxScanFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(outside, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, target, reason string }{
		{"oversized", big, "larger than the scan size limit"},
		{"fifo", fifo, "not a regular file"},
		{"dangling", filepath.Join(outside, "missing"), "unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Symlink(tc.target, filepath.Join(dir, ".env")); err != nil {
				t.Fatal(err)
			}
			done := make(chan []Finding, 1)
			go func() { done <- scanFiles(dir, mustCompileDLPPatterns(t)) }()
			select {
			case findings := <-done:
				if len(findings) != 1 || !strings.Contains(findings[0].Message, "Could not inspect .env for secrets ("+tc.reason+")") {
					t.Fatalf("got %+v, want one %q inspection warning", findings, tc.reason)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("scan blocked on a symlinked special file")
			}
		})
	}
}

func TestScanFiles_UnreadableDirectoryReportsUninspected(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode 000 directories")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, ".env"), []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Chmod(locked, 0o700) })
	findings := scanFiles(dir, mustCompileDLPPatterns(t))
	if len(findings) != 1 || !strings.Contains(findings[0].Message, "Could not inspect locked for secrets (unreadable)") {
		t.Fatalf("unreadable directory must report an inspection warning, got %+v", findings)
	}
}

// --- AdjustScoreForFindings tests ---

func TestScanFiles_UnreadableRootNamesTheDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode 000 directories")
	}
	dir := t.TempDir()
	if err := syscall.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Chmod(dir, 0o700) })
	findings := scanFiles(dir, mustCompileDLPPatterns(t))
	if len(findings) != 1 || !strings.Contains(findings[0].Message, "Could not inspect "+dir+" for secrets (unreadable)") {
		t.Fatalf("unreadable scan root must report an inspection warning naming it, got %+v", findings)
	}
}

func TestReadSecretCandidate_FIFODoesNotBlock(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), ".env")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	type result struct {
		data   []byte
		reason string
	}
	done := make(chan result, 1)
	go func() {
		data, reason := readSecretCandidate(fifo)
		done <- result{data, reason}
	}()
	select {
	case r := <-done:
		if r.reason != "not a regular file" || r.data != nil {
			t.Fatalf("FIFO read = %q, %q; want refusal", r.data, r.reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reading a FIFO candidate blocked")
	}
}
