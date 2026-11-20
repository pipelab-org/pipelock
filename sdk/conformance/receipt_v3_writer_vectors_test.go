// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func v3WriterRecipes(t *testing.T) []v3Recipe {
	t.Helper()
	var recipes []v3Recipe
	for _, tc := range []struct {
		group   int
		name    string
		rotated bool
	}{
		{group: 5, name: "writer-rollover"},
		{group: 7, name: "writer-completed-action"},
		{group: 9, name: "writer-switch-legacy"},
		{group: 9, name: "writer-switch-endorsed-rotation", rotated: true},
	} {
		dir := t.TempDir()
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
		recipe.files = v3ReadWrittenCorpus(t, dir)
		recipes = append(recipes, recipe)
	}
	return recipes
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []v3File
	for _, entry := range entries {
		data, err := root.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, v3File{name: entry.Name(), bytes: data})
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
	const endorsementName = "rotation-endorsement.json"
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
		if name == "expect.json" {
			continue
		}
		data, err := root.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if name == rootKey || name == nextKey {
			key := strings.TrimSpace(string(data))
			pins = append(pins, key)
			if name == rootKey {
				recipe.request.Keys = []string{key, hex.EncodeToString(v3Public(opts.SigningKey))}
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(opts.Dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	opts.PriorSignerKeys, err = v3.DecodeKeys(pins)
	if err != nil {
		t.Fatal(err)
	}
	recipe.verdict, recipe.code = "VALID PREFIX, END UNPROVEN", "LEGACY_END_UNPROVEN"
	recipe.request.Endorsements = []string{endorsementName}
	recipe.request.AllowPrefix = true
}
