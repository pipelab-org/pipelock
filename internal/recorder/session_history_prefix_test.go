// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestHistoryPrefixAppendsAndRotation(t *testing.T) {
	for _, at := range []int{1, 4} {
		t.Run(strconv.Itoa(at), func(t *testing.T) {
			dir := t.TempDir()
			writeHistoryShard(t, dir, "live", 0, 2)
			name := writeHistoryShard(t, dir, "live", 2, 2)
			path := filepath.Join(dir, name)
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			bound := SessionHistoryPrefix{File: name, End: before.Size()}
			count := 0
			err = WalkSessionHistoryPrefix(dir, "live", bound, func(Entry) error {
				count++
				if count == at {
					appendHistoryPrefixTest(t, path, historyLines(t, historyEntries(t, "live", 4, 1, "append")))
					writeHistoryShard(t, dir, "live", 5, 2)
					writeUnrelatedEvidence(t, dir, 1)
				}
				return nil
			})
			if err != nil || count != 4 {
				t.Fatalf("count=%d err=%v", count, err)
			}
			// The strict offline reader must still reject the same interleaving.
			err = WalkSessionHistory(dir, "live", func(e Entry) error {
				if e.Sequence == 0 {
					appendHistoryPrefixTest(t, filepath.Join(dir, "evidence-live-5.jsonl"), historyLines(t, historyEntries(t, "live", 7, 1, "append")))
				}
				return nil
			})
			if !errors.Is(err, ErrEvidenceChanged) {
				t.Fatalf("strict reader accepted mutation: %v", err)
			}
		})
	}
}

func appendHistoryPrefixTest(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryPrefixInvalidLocationAndSession(t *testing.T) {
	dir := t.TempDir()
	name := writeHistoryShard(t, dir, "live", 0, 1)
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	prefix := SessionHistoryPrefix{File: name, End: info.Size()}
	for _, tc := range []struct{ location, session string }{
		{filepath.Join(dir, name), "live"},
		{dir, "../live"},
	} {
		t.Run(tc.session+"/"+filepath.Base(tc.location), func(t *testing.T) {
			called := false
			err := WalkSessionHistoryPrefix(tc.location, tc.session, prefix, func(Entry) error {
				called = true
				return nil
			})
			if err == nil || called {
				t.Fatalf("invalid input: called=%v err=%v", called, err)
			}
		})
	}
}

func TestHistoryPrefixRefusesChanges(t *testing.T) {
	for _, scenario := range []string{"shrink_before", "shrink_during", "closed_append", "replace", "delete", "insert", "duplicate", "duplicate_after", "torn", "oversize", "bad_session", "path", "negative", "nil_consumer"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			old := writeHistoryShard(t, dir, "live", 0, 1)
			name := writeHistoryShard(t, dir, "live", 2, 2)
			path := filepath.Join(dir, name)
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			bound := SessionHistoryPrefix{File: name, End: int64(len(data))}
			short := int64(strings.IndexByte(string(data), '\n') + 1)
			switch scenario {
			case "shrink_before":
				if err := os.Truncate(path, short); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				if err := os.WriteFile(filepath.Join(dir, "evidence-live-00.jsonl"), historyLines(t, historyEntries(t, "live", 0, 1, "same")), 0o600); err != nil {
					t.Fatal(err)
				}
			case "duplicate_after":
				// A tie lexically after the observed shard is still ambiguous.
				if err := os.Rename(path, filepath.Join(dir, "evidence-live-02.jsonl")); err != nil {
					t.Fatal(err)
				}
				bound.File = "evidence-live-02.jsonl"
				if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "torn":
				bound.End--
			case "oversize":
				bound.End++
			case "bad_session":
				bound.File = "evidence-other-2.jsonl"
			case "path":
				bound.File = "../" + name
			case "negative":
				bound.End = -1
			}
			consume := func(e Entry) error {
				if e.Sequence != 0 {
					return nil
				}
				switch scenario {
				case "shrink_during":
					if err := os.Truncate(path, short); err != nil {
						t.Fatal(err)
					}
				case "closed_append":
					appendHistoryPrefixTest(t, filepath.Join(dir, old), historyLines(t, historyEntries(t, "live", 1, 1, "changed")))
				case "replace":
					if err := os.Rename(path, path+".saved"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, data, 0o600); err != nil {
						t.Fatal(err)
					}
				case "delete":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "insert":
					writeHistoryShard(t, dir, "live", 1, 1)
				}
				return nil
			}
			if scenario == "nil_consumer" {
				consume = nil
			}
			err = WalkSessionHistoryPrefix(dir, "live", bound, consume)
			if err == nil || IsEvidenceUnavailable(err) {
				t.Fatalf("expected refusal, got %v", err)
			}
		})
	}
}

func TestHistoryPrefixLineBoundaryShrinkWhileReading(t *testing.T) {
	dir := t.TempDir()
	name := writeHistoryShard(t, dir, "live", 0, 2)
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	bound := SessionHistoryPrefix{File: name, End: int64(len(data))}
	loc := historyLocation(t, dir)
	// The parser buffers both lines, so only the post-read size check detects
	// removal of the already buffered last line. No receipt-head check helps it.
	err = walkHistoryPrefixShard(loc, "live", bound, func(e Entry) error {
		if e.Sequence == 0 {
			if err := os.Truncate(path, int64(strings.IndexByte(string(data), '\n')+1)); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	if !errors.Is(err, ErrEvidenceRefused) {
		t.Fatalf("buffered shrink accepted: %v", err)
	}
}

func TestHistoryPrefixMultipleWindows(t *testing.T) {
	dir := t.TempDir()
	var name string
	for i := range sessionHistoryWindow + 1 {
		name = writeHistoryShard(t, dir, "live", uint64(i), 1)
	}
	path := filepath.Join(dir, name)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	err = WalkSessionHistoryPrefix(dir, "live", SessionHistoryPrefix{File: name, End: info.Size()}, func(Entry) error {
		count++
		if count == 1 {
			appendHistoryPrefixTest(t, path, historyLines(t, historyEntries(t, "live", sessionHistoryWindow+1, 1, "append")))
		}
		return nil
	})
	if err != nil || count != sessionHistoryWindow+1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

// The observed shard is already gone before the walk starts (no inventory to
// compare against yet). Only the foundPrefix guard can refuse this.
func TestHistoryPrefixMissingBeforeWalk(t *testing.T) {
	dir := t.TempDir()
	writeHistoryShard(t, dir, "live", 0, 1)
	name := writeHistoryShard(t, dir, "live", 2, 2)
	path := filepath.Join(dir, name)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	bound := SessionHistoryPrefix{File: name, End: info.Size()}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	count := 0
	err = WalkSessionHistoryPrefix(dir, "live", bound, func(Entry) error { count++; return nil })
	if !errors.Is(err, ErrEvidenceRefused) || !strings.Contains(err.Error(), "observed evidence file is missing") {
		t.Fatalf("missing observed shard: count=%d err=%v", count, err)
	}
	t.Logf("refused: %v", err)
}
