// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStreamWriterRejectedOptionsLeaveDirectoryReusable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*StreamWriterOptions)
		want   string
	}{
		{"missing directory", func(o *StreamWriterOptions) { o.Dir = "" }, "directory is required"},
		{"short private key", func(o *StreamWriterOptions) { o.SigningKey = o.SigningKey[:1] }, "not an Ed25519 private key"},
		{"inconsistent private key", func(o *StreamWriterOptions) { o.SigningKey[len(o.SigningKey)-1] ^= 1 }, "does not match its public key"},
		{"scanner absent", func(o *StreamWriterOptions) { o.Coverage.ContentScan = true; o.Detector = nil }, "requires a detector"},
		{"fractional heartbeat", func(o *StreamWriterOptions) { o.Heartbeat = time.Millisecond }, "nonnegative whole number of seconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := writerTestOptions(dir)
			tc.change(&opts)
			writer, err := OpenStreamWriter(t.Context(), opts)
			if writer != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("OpenStreamWriter returned writer=%t, err=%v, want %q", writer != nil, err, tc.want)
			}
			if has, err := DirectoryHasV3(dir); has || err != nil {
				t.Fatalf("failed startup left v3 evidence: %t, %v", has, err)
			}
			writer, err = OpenStreamWriter(t.Context(), writerTestOptions(dir))
			if err != nil {
				t.Fatalf("open after rejected startup: %v", err)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectoryHasV3(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "ordinary.jsonl")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", filepath.Join(dir, "missing"), dir} {
		if has, err := DirectoryHasV3(path); has || err != nil {
			t.Fatalf("DirectoryHasV3(%q) = %t, %v, want false, nil", path, has, err)
		}
	}
	if has, err := DirectoryHasV3(file); has || err == nil || !strings.Contains(err.Error(), "read receipt evidence directory") {
		t.Fatalf("DirectoryHasV3(non-directory) = %t, %v", has, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "damaged"+layoutFileSuffix), []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if has, err := DirectoryHasV3(dir); !has || err != nil {
		t.Fatalf("DirectoryHasV3(damaged evidence) = %t, %v, want true, nil", has, err)
	}
}

func TestStreamWriterStartupPublicationFailureLeavesDirectoryReusable(t *testing.T) {
	injected := errors.New("opening record storage failure")
	for _, tc := range []struct {
		name      string
		want      error
		configure func(*StreamWriterOptions)
	}{
		{
			name: "lineage randomness", want: io.ErrUnexpectedEOF,
			configure: func(opts *StreamWriterOptions) { opts.Random = strings.NewReader("short") },
		},
		{
			name: "stream randomness", want: io.EOF,
			configure: func(opts *StreamWriterOptions) { opts.Random = strings.NewReader(strings.Repeat("a", 16)) },
		},
		{
			name: "temporary file creation", want: injected,
			configure: func(opts *StreamWriterOptions) {
				opts.CreateTempFile = func(string, string) (StreamFile, error) { return nil, injected }
			},
		},
		{
			name: "opening record write", want: injected,
			configure: func(opts *StreamWriterOptions) {
				opts.CreateTempFile = faultOpeningRecord(injected, nil)
			},
		},
		{
			name: "opening record sync", want: injected,
			configure: func(opts *StreamWriterOptions) {
				opts.CreateTempFile = faultOpeningRecord(nil, injected)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := writerTestOptions(dir)
			tc.configure(&opts)
			writer, err := OpenStreamWriter(t.Context(), opts)
			if writer != nil {
				_ = writer.Close(t.Context(), nil)
			}
			if writer != nil || !errors.Is(err, tc.want) {
				t.Fatalf("startup = %t, %v, want %v", writer != nil, err, tc.want)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed startup left evidence artifacts: %v, %v", entries, err)
			}
			restarted := requireWriter(t, writerTestOptions(dir), localWriterStorage())
			if err := restarted.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func faultOpeningRecord(writeErr, syncErr error) func(string, string) (StreamFile, error) {
	return func(dir, pattern string) (StreamFile, error) {
		file, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return errorWriterFile{StreamFile: file, writeErr: writeErr, syncErr: syncErr}, nil
	}
}
