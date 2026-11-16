// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateEvidenceFileDigestRefusesRestoredTimeTornWrite(t *testing.T) {
	dir := t.TempDir()
	rec := newDigestRecorder(t, dir)
	for range 12 {
		if err := rec.Record(Entry{SessionID: "digest", Type: "decision", Summary: strings.Repeat("a", 2000)}); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files: %v %v", files, err)
	}
	path := files[0]
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	_, err = ValidateEvidenceFileDigest(path, func(Entry) error {
		if !changed {
			changed = true
			f, e := os.OpenFile(filepath.Clean(path), os.O_WRONLY, 0)
			if e != nil {
				return e
			}
			_, e = f.WriteAt([]byte("x"), info.Size()-1)
			_ = f.Close()
			if e != nil {
				return e
			}
			return os.Chtimes(path, info.ModTime(), info.ModTime())
		}
		return nil
	})
	if !changed {
		t.Fatal("writer did not run")
	}
	if !errors.Is(err, ErrTornTail) {
		t.Fatalf("validation after concurrent write: %v, want torn tail", err)
	}
	if err := ValidateEvidenceFile(path, nil); !errors.Is(err, ErrTornTail) {
		t.Fatalf("stable full validation: %v, want torn tail", err)
	}
}
