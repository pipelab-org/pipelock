// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeDigestShard(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence-digest-0.jsonl")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEvidenceFileDigestsDescribeExactBytes(t *testing.T) {
	data := []byte("{\"a\":1}\n{\"b\":2}\n")
	path := writeDigestShard(t, data)
	want := EvidenceFileDigest{Size: int64(len(data)), SHA256: sha256.Sum256(data)}

	got, err := DigestEvidenceFile(path)
	if err != nil || got != want {
		t.Fatalf("DigestEvidenceFile = %+v, %v; want %+v", got, err, want)
	}
	var seen int
	got, err = ValidateEvidenceFileDigest(path, func(Entry) error { seen++; return nil })
	if err == nil || seen != 0 {
		// The fixture lines are not recorder entries; validation refuses them
		// before any digest is reported.
		t.Fatalf("non-entry shard validated: digest=%+v err=%v seen=%d", got, err, seen)
	}
	if got != (EvidenceFileDigest{}) {
		t.Fatalf("failed validation reported digest %+v", got)
	}
}

func TestValidateEvidenceFileDigestMatchesWholeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence")
	rec := newDigestRecorder(t, path)
	for i := range 3 {
		if err := rec.Record(Entry{SessionID: "digest", Type: "decision", Summary: "allow", Detail: map[string]int{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join(path, "evidence-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var entries int
	got, err := ValidateEvidenceFileDigest(files[0], func(Entry) error { entries++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if entries == 0 {
		t.Fatal("validator saw no entries")
	}
	if want := (EvidenceFileDigest{Size: int64(len(data)), SHA256: sha256.Sum256(data)}); got != want {
		t.Fatalf("digest %+v, want %+v", got, want)
	}
	plain, err := DigestEvidenceFile(files[0])
	if err != nil || plain != got {
		t.Fatalf("DigestEvidenceFile = %+v, %v; want the validated digest", plain, err)
	}
	if err := ValidateEvidenceFile(files[0], nil); err != nil {
		t.Fatalf("ValidateEvidenceFile: %v", err)
	}
}

func TestDigestEvidenceFileRefusesSymlinksAndMissingFiles(t *testing.T) {
	target := writeDigestShard(t, []byte("{}\n"))
	link := filepath.Join(t.TempDir(), "link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := DigestEvidenceFile(link); !errors.Is(err, ErrEvidenceRefused) {
		t.Fatalf("symlink digest err = %v, want ErrEvidenceRefused", err)
	}
	if _, err := ValidateEvidenceFileDigest(link, nil); !errors.Is(err, ErrEvidenceRefused) {
		t.Fatalf("symlink validation err = %v, want ErrEvidenceRefused", err)
	}
	if _, err := DigestEvidenceFile(filepath.Join(t.TempDir(), "absent.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing digest err = %v", err)
	}
}

func TestCountingWriterCountsWrittenBytes(t *testing.T) {
	h := sha256.New()
	c := &countingWriter{w: h}
	if n, err := c.Write([]byte("abc")); n != 3 || err != nil || c.n != 3 {
		t.Fatalf("write n=%d err=%v count=%d", n, err, c.n)
	}
}

func newDigestRecorder(t *testing.T, dir string) *Recorder {
	t.Helper()
	rec, err := New(Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	return rec
}
