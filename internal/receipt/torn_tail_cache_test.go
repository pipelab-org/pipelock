// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// cachedTailRun is a live run split across several shards, as a long-lived
// proxy's run is.
type cachedTailRun struct {
	run  testRun
	keys []string
}

func startShardedRun(t *testing.T) cachedTailRun {
	t.Helper()
	_, priv := generateTestKey(t)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), CheckpointInterval: 1000, MaxEntriesPerFile: 3}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor, Session: session})
	if err := e.InitError(); err != nil {
		t.Fatal(err)
	}
	run := testRun{rec: rec, e: e, session: session}
	run.openAndEmit(t, 8)
	return cachedTailRun{run: run, keys: []string{e.SignerKeyHex()}}
}

func (c cachedTailRun) shards(t *testing.T) []string {
	t.Helper()
	files, err := recorderFiles(c.run.rec.Dir(), c.run.session)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 3 {
		t.Fatalf("want a multi-shard run, got %d shards", len(files))
	}
	return files
}

func (c cachedTailRun) check(cache *TailCheckCache) error {
	return CheckSessionTailCached(c.run.rec, c.run.session, c.keys, cache)
}

// countFullValidations records which shards are parsed and verified in full.
func countFullValidations(t *testing.T) *[]string {
	t.Helper()
	var validated []string
	orig := validateShardFile
	validateShardFile = func(path string, validate func(recorder.Entry) error) (recorder.EvidenceFileDigest, error) {
		validated = append(validated, path)
		return orig(path, validate)
	}
	t.Cleanup(func() { validateShardFile = orig })
	return &validated
}

func TestCheckSessionTailCachedValidatesOnlyChangedShards(t *testing.T) {
	c := startShardedRun(t)
	validated := countFullValidations(t)
	var cache TailCheckCache

	files := c.shards(t)
	if err := c.check(&cache); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*validated, files) {
		t.Fatalf("first check validated %v, want every shard %v", *validated, files)
	}

	*validated = nil
	if err := c.check(&cache); err != nil {
		t.Fatal(err)
	}
	if len(*validated) != 0 {
		t.Fatalf("unchanged run re-validated %v", *validated)
	}

	// New records land in the active shard until it fills, then in new
	// shards. Exactly the shards whose bytes changed or are new are parsed.
	for _, appended := range []int{1, 4} {
		before := shardSizes(t, c.shards(t))
		for range appended {
			emitOne(t, c.run.e)
		}
		var want []string
		for _, file := range c.shards(t) {
			if size, ok := before[file]; !ok || size != shardSizes(t, []string{file})[file] {
				want = append(want, file)
			}
		}
		if len(want) == 0 {
			t.Fatal("appends changed no shard; the fixture proves nothing")
		}
		*validated = nil
		if err := c.check(&cache); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(*validated, want) {
			t.Fatalf("after %d appends validated %v, want only the changed and new shards %v", appended, *validated, want)
		}
	}
}

func shardSizes(t *testing.T, files []string) map[string]int64 {
	t.Helper()
	sizes := make(map[string]int64, len(files))
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		sizes[file] = info.Size()
	}
	return sizes
}

// flipStoredHash changes one hex digit of the first record's stored hash. The
// file keeps its size, so only its bytes reveal the change.
func flipStoredHash(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte(`"hash":"`)
	i := bytes.Index(data, marker)
	if i < 0 {
		t.Fatal("no stored hash in shard")
	}
	tampered := bytes.Clone(data)
	at := i + len(marker)
	if tampered[at] == '0' {
		tampered[at] = '1'
	} else {
		tampered[at] = '0'
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCheckSessionTailCachedDetectsSameSizeTamperInVerifiedShard(t *testing.T) {
	for _, shard := range []string{"first", "middle"} {
		t.Run(shard, func(t *testing.T) {
			c := startShardedRun(t)
			var cache TailCheckCache
			if err := c.check(&cache); err != nil {
				t.Fatal(err)
			}
			files := c.shards(t)
			target := files[0]
			if shard == "middle" {
				target = files[len(files)/2]
			}
			original := flipStoredHash(t, target)

			for attempt := range 2 {
				if err := c.check(&cache); err == nil {
					t.Fatalf("attempt %d: tamper in a cached shard accepted", attempt)
				}
			}
			if err := c.check(nil); err == nil {
				t.Fatal("full validation accepted the tamper; the fixture proves nothing")
			}

			// Restoring the bytes restores the verdict, so the refusal came
			// from the change and not from a poisoned cache.
			if err := os.WriteFile(target, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := c.check(&cache); err != nil {
				t.Fatalf("restored run refused: %v", err)
			}
		})
	}
}

func TestCheckSessionTailCachedRevalidatesForNewKeysOrSession(t *testing.T) {
	c := startShardedRun(t)
	var cache TailCheckCache
	if err := c.check(&cache); err != nil {
		t.Fatal(err)
	}
	files := c.shards(t)
	validated := countFullValidations(t)

	// A key set that no longer holds the run's signer must refuse, as a full
	// validation does; a cached verdict for the old set must not answer.
	otherPub, _ := generateTestKey(t)
	otherKey := hex.EncodeToString(otherPub)
	if err := CheckSessionTailCached(c.run.rec, c.run.session, []string{otherKey}, &cache); err == nil {
		t.Fatal("cached shards accepted under a key set without their signer")
	}
	if len(*validated) == 0 || (*validated)[0] != files[0] {
		t.Fatalf("key change did not restart validation at the first shard: %v", *validated)
	}

	// Key order and duplicates do not change the set.
	if err := c.check(&cache); err != nil {
		t.Fatal(err)
	}
	*validated = nil
	keys := []string{c.keys[0], c.keys[0]}
	if err := CheckSessionTailCached(c.run.rec, c.run.session, keys, &cache); err != nil {
		t.Fatal(err)
	}
	if len(*validated) != 0 {
		t.Fatalf("equal key set re-validated %v", *validated)
	}

	// Another session never inherits this run's cache.
	if err := CheckSessionTailCached(c.run.rec, c.run.session+"-other", c.keys, &cache); err != nil {
		t.Fatal(err)
	}
	*validated = nil
	if err := c.check(&cache); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*validated, files) {
		t.Fatalf("returning to the run after another session validated %v, want %v", *validated, files)
	}
}

func TestCheckSessionTailCachedRevalidatesAfterRemovedShard(t *testing.T) {
	c := startShardedRun(t)
	var cache TailCheckCache
	if err := c.check(&cache); err != nil {
		t.Fatal(err)
	}
	files := c.shards(t)
	if err := os.Remove(files[1]); err != nil {
		t.Fatal(err)
	}
	if err := c.check(&cache); err == nil {
		t.Fatal("a run with a missing shard passed the cached check")
	}
	if err := c.check(nil); err == nil {
		t.Fatal("full validation accepted the missing shard; the fixture proves nothing")
	}
}

func TestCheckSessionTailNilCacheValidatesEveryShard(t *testing.T) {
	c := startShardedRun(t)
	files := c.shards(t)
	validated := countFullValidations(t)
	for range 2 {
		if err := CheckSessionTail(c.run.rec, c.run.session, c.keys); err != nil {
			t.Fatal(err)
		}
	}
	if want := append(slices.Clone(files), files...); !slices.Equal(*validated, want) {
		t.Fatalf("uncached checks validated %v, want every shard twice", *validated)
	}
}

// TestCheckSessionTailCachedRelinksShardsAfterAChangedOne drops the last
// record of a verified shard. That shard alone still validates, so only the
// next shard's link to it reveals the loss; a cached later shard must not
// carry its old state past the change.
func TestCheckSessionTailCachedRelinksShardsAfterAChangedOne(t *testing.T) {
	c := startShardedRun(t)
	var cache TailCheckCache
	if err := c.check(&cache); err != nil {
		t.Fatal(err)
	}
	files := c.shards(t)
	data, err := os.ReadFile(filepath.Clean(files[0]))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if len(lines) < 3 || len(lines[len(lines)-1]) != 0 {
		t.Fatalf("first shard has %d lines", len(lines))
	}
	truncated := bytes.Join(lines[:len(lines)-2], nil)
	if err := os.WriteFile(files[0], truncated, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.check(nil); err == nil {
		t.Fatal("full validation accepted the dropped record; the fixture proves nothing")
	}
	for attempt := range 2 {
		if err := c.check(&cache); err == nil {
			t.Fatalf("attempt %d: dropped record hidden by a cached later shard", attempt)
		}
	}
}

func TestCheckSessionTailCachedDistinguishesNilAndEmptyKeys(t *testing.T) {
	c := startShardedRun(t)
	var cache TailCheckCache
	if err := CheckSessionTailCached(c.run.rec, c.run.session, nil, &cache); err != nil {
		t.Fatal(err)
	}
	if err := CheckSessionTailCached(c.run.rec, c.run.session, []string{}, nil); err == nil {
		t.Fatal("full check accepted empty signer set")
	}
	if err := CheckSessionTailCached(c.run.rec, c.run.session, []string{}, &cache); err == nil {
		t.Fatal("cached check accepted empty signer set")
	}
}

func TestCheckSessionTailCachedSeparatesSignerKeys(t *testing.T) {
	c := startShardedRun(t)
	var cache TailCheckCache
	if err := CheckSessionTailCached(c.run.rec, c.run.session, []string{c.keys[0], "zzzz"}, &cache); err != nil {
		t.Fatal(err)
	}
	keys := []string{c.keys[0] + "\nzzzz"}
	if err := CheckSessionTailCached(c.run.rec, c.run.session, keys, nil); err == nil {
		t.Fatal("full check accepted different signer set")
	}
	if err := CheckSessionTailCached(c.run.rec, c.run.session, keys, &cache); err == nil {
		t.Fatal("cached check accepted different signer set")
	}
}
