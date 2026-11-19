// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestReadBoundedAELLineCountsGrowthAcrossRecords(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int64
		fail  bool
	}{
		{"within limit", 11, false},
		{"appended line exceeds limit", 10, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stream.jsonl")
			if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path) // #nosec G304 -- path is inside this test's temporary directory.
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			initial, err := file.Stat()
			if err != nil || initial.Size() > tc.limit {
				t.Fatalf("initial stream size = %v, %v", initial, err)
			}
			writer, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- path is inside this test's temporary directory.
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.WriteString("more\n"); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			r := bufio.NewReader(file)
			var total int64
			if line, err := readBoundedAELLine(r, &total, tc.limit); err != nil || string(line) != "first\n" || total != 6 {
				t.Fatalf("first line = %q, %v, total=%d", line, err, total)
			}
			line, err := readBoundedAELLine(r, &total, tc.limit)
			if tc.fail {
				if !errors.Is(err, ErrStreamTooLarge) || total != 6 {
					t.Fatalf("growth beyond limit = %q, %v, total=%d", line, err, total)
				}
			} else if err != nil || string(line) != "more\n" || total != 11 {
				t.Fatalf("bounded stream = %q, %v, total=%d", line, err, total)
			}
		})
	}
}

func TestVerifyRunClassifiesOversizeAtFinalStat(t *testing.T) {
	emitter, dir, signer := newIncrementalRun(t)
	closeIncrementalRun(t, emitter)
	_, err := verifyRunWithOptions(dir, incrementalRunID, signer, true, verification.Options{}, func(file *os.File) (os.FileInfo, error) {
		if err := os.Truncate(file.Name(), maxVerifyStreamBytes+1); err != nil {
			return nil, err
		}
		return file.Stat()
	})
	if !errors.Is(err, ErrStreamTooLarge) {
		t.Fatalf("VerifyRun error=%v, want %v", err, ErrStreamTooLarge)
	}
}
