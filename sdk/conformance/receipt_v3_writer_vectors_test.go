// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func v3RunWriterRecipes(t *testing.T) {
	t.Helper()
	for _, tc := range []struct {
		group   int
		name    string
		rotated bool
	}{
		{group: 5, name: "writer-rollover"},
		{group: 7, name: "writer-completed-action"},
		{group: 7, name: "writer-operational-strays"},
		{group: 7, name: "writer-lone-chain-link"},
		{group: 9, name: "writer-switch-legacy"},
		{group: 9, name: "writer-switch-journal"},
		{group: 9, name: "writer-switch-rotated-legacy", rotated: true},
	} {
		t.Run(fmt.Sprintf("g%02d-%s", tc.group, tc.name), func(t *testing.T) {
			dir := t.TempDir()
			lock, err := recorder.AcquireEvidenceCeremonyLock(dir)
			if err != nil {
				if !strings.Contains(err.Error(), "ceremony locking is unsupported") {
					t.Fatal(err)
				}
				v3RunFrozenWriterRecipe(t, tc.group, tc.name)
				return
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			key := v3Key("first")
			random := bytes.NewReader(bytes.Join([][]byte{
				bytes.Repeat([]byte{0x11}, 16),
				bytes.Repeat([]byte{0x22}, 16),
				bytes.Repeat([]byte{0x33}, 16),
			}, nil))
			opts := v3.StreamWriterOptions{
				Dir: dir, SigningKey: key, Random: random,
				Clock:      func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
				Identity:   v3.Writer{Instance: "example", Product: "Pipelock", Version: "3"},
				PolicyHash: v3.Digest(nil),
				Coverage: v3.Coverage{
					ReceiptsRequired: true, Surfaces: []string{"fetch"},
					RedactionRuleset: v3.Ruleset{Hash: v3.Digest(nil), ID: "example", Version: "1"},
				},
			}
			req := v3Request{Directory: true}
			recipe := v3Recipe{group: tc.group, name: tc.name, verdict: "VALID", request: req}
			if tc.rotated {
				v3PrepareRotatedLegacy(t, &opts, &recipe)
			} else if tc.name == "writer-switch-journal" {
				const journal = "{\"defer_id\":\"example\",\"state\":\"deferred_held\"}\n" +
					"{\"defer_id\":\"example\",\"state\":\"resolved_block\"}\n"
				if err := os.WriteFile(filepath.Join(dir, "deferred-actions.jsonl"), []byte(journal), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if tc.group == 9 {
				legacy, err := os.ReadFile("testdata/frozen/v1/action-receipt-v1-chain.jsonl")
				if err != nil {
					t.Fatal(err)
				}
				const path = "evidence-conformance-session-0.jsonl"
				if err := os.WriteFile(filepath.Join(dir, path), legacy, 0o600); err != nil {
					t.Fatal(err)
				}
				keys := v3LegacyWriterKeys(t, path, legacy)
				opts.PriorSignerKeys, err = v3.DecodeKeys(keys)
				if err != nil {
					t.Fatal(err)
				}
				recipe.request.Keys = append(keys, hex.EncodeToString(v3Public(key)))
				recipe.request.AllowPrefix = true
				recipe.verdict, recipe.code = "VALID PREFIX, END UNPROVEN", "LEGACY_END_UNPROVEN"
			}
			w, err := v3.OpenStreamWriter(t.Context(), opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = w.Close(ctx, nil)
			})
			switch tc.group {
			case 5:
				if err := w.WriteHeartbeat(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := w.Rollover(t.Context()); err != nil {
					t.Fatal(err)
				}
			case 7:
				v3WriteCorpusAction(t, w)
			}
			if err := w.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			if tc.name == "writer-operational-strays" {
				if err := os.Mkdir(filepath.Join(dir, "operational"), 0o750); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"operational/.keep", ".receipt-v3-tmp-leftover", "stray.txt"} {
					if err := os.WriteFile(filepath.Join(dir, name), []byte("ignored\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.name == "writer-lone-chain-link" {
				if err := os.WriteFile(filepath.Join(dir, "chain-link-alone.json"), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			recipe.files = v3ReadWrittenCorpus(t, dir)
			v3RunRecipe(t, recipe)
		})
	}
}

func v3RunFrozenWriterRecipe(t *testing.T, group int, name string) {
	t.Helper()
	if *updateReceiptV3 {
		t.Skip("writer fixture regeneration requires receipt ceremony locking")
	}
	dir := filepath.Join(v3Corpus, filepath.Base(t.Name()))
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	raw, err := root.ReadFile("request.json")
	if err != nil {
		t.Fatal(err)
	}
	var request v3Request
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	var expected struct {
		Verdict string
	}
	raw, err = root.ReadFile("expect.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	recipe := v3Recipe{group: group, name: name, code: request.Finding, verdict: expected.Verdict, request: request}
	for _, input := range request.Inputs {
		raw, err := root.ReadFile(input)
		if err != nil {
			t.Fatal(err)
		}
		recipe.files = append(recipe.files, v3File{name: input, bytes: raw})
	}
	v3RunRecipe(t, recipe)
}

func v3WriteCorpusAction(t *testing.T, writer *v3.StreamWriter) {
	t.Helper()
	attempt := int64(1)
	action := v3.Action{
		ActionID: "request", ActionType: "read", Actor: "example", Attempt: &attempt,
		Caller: v3.Caller{Authn: "none"}, Data: v3.Data{SideEffectClass: "external_read", Reversibility: "full"},
		EffectBoundary: "upstream_send", EffectRelation: "before", Method: http.MethodGet,
		Phase: "intent", Principal: "local", Target: "https://api.vendor.example", Transport: "fetch", Verdict: "allow",
	}
	policy := v3.CapturePolicy(v3.Digest([]byte("example policy snapshot")))
	if err := writer.WriteAction(t.Context(), action, policy); err != nil {
		t.Fatal(err)
	}
	action.EffectRelation, action.Phase, action.OutcomeClass = "after", "outcome", "completed"
	if err := writer.WriteAction(t.Context(), action, policy); err != nil {
		t.Fatal(err)
	}
}

func v3ReadWrittenCorpus(t *testing.T, dir string) []v3File {
	t.Helper()
	var files []v3File
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		name, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Clean(path)) // #nosec G122 -- writer-created test directory, not shared with untrusted processes.
		if err != nil {
			return err
		}
		files = append(files, v3File{name: filepath.ToSlash(name), bytes: data})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func v3LegacyWriterKeys(t *testing.T, path string, data []byte) []string {
	t.Helper()
	entries, err := recorder.ReadHistoryEntriesFromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	chain, _, found, err := actionreceipt.RecorderFileChains(path, entries)
	if err != nil || !found || len(chain) == 0 {
		t.Fatalf("read legacy chain: %v", err)
	}
	return []string{chain[0].SignerKey}
}

func v3PrepareRotatedLegacy(t *testing.T, opts *v3.StreamWriterOptions, recipe *v3Recipe) {
	t.Helper()
	const fixture = "testdata/parity/rotated"
	const rootKey = "signer-key.hex"
	const nextKey = "rotated-signer-key.hex"
	root, err := os.OpenRoot(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	entries, err := os.ReadDir(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var pins []string
	for _, entry := range entries {
		name := entry.Name()
		if name == "expect.json" || name == "rotation-endorsement.json" {
			continue
		}
		data, err := root.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if name == rootKey || name == nextKey {
			key := strings.TrimSpace(string(data))
			pins = append(pins, key)
			continue
		}
		if err := os.WriteFile(filepath.Join(opts.Dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Mixed directories verify legacy chains with pinned keys only, so the
	// verifier pins both legacy signers alongside the v3 writer key.
	recipe.request.Keys = append(slices.Clone(pins), hex.EncodeToString(v3Public(opts.SigningKey)))
	opts.PriorSignerKeys, err = v3.DecodeKeys(pins)
	if err != nil {
		t.Fatal(err)
	}
	recipe.verdict, recipe.code = "VALID PREFIX, END UNPROVEN", "LEGACY_END_UNPROVEN"
	recipe.request.AllowPrefix = true
}
