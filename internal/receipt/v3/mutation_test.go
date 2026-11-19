// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type mutationRecipe struct {
	Finding       string
	Inputs        []string
	Keys          []string
	AllowPrefix   bool `json:"allow_prefix"`
	AllowUnpinned bool `json:"allow_unpinned"`
	Format        string
}

func TestCorpusCheckMutations(t *testing.T) {
	root := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "v3")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	// These are the checks exercised by the wire, body, trust and
	// determinism groups. History, decision and cutover groups are generated
	// from the writer and extend this list.
	targets := strings.Fields(
		"LINE_LAYOUT LINE_SIZE FILE_LAYOUT PAYLOAD_LAYOUT COMMON_SCHEMA SIGNER_MISSING " +
			"SIGNATURE_KEY SIGNATURE_SCALAR SIGNATURE_POINT SIGNATURE_EQUATION STREAM_ORDER " +
			"BODY_SCHEMA TRUST DATA_AFTER_CLOSE V3_CONTENT_UNCLAIMED UNRECOGNIZED_FILE UNKNOWN_PROFILE UNKNOWN_CRIT " +
			"UNKNOWN_CONTROL NO_EVIDENCE DECISIONS_NOT_APPRAISED ACTION_UNINTERPRETED END_UNPROVEN " +
			"HEARTBEAT_GAP CLOCK_REGRESSION TORN_TAIL EVENT_UNINTERPRETED FORK NORMALIZATION_UNKNOWN")
	seen := map[string]bool{}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "g") {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		recipe := readMutationRecipe(t, dir)
		if recipe.Finding == "" || !slices.Contains(targets, recipe.Finding) || seen[recipe.Finding] {
			continue
		}
		t.Run(recipe.Finding, func(t *testing.T) {
			seen[recipe.Finding] = true
			keys, err := DecodeKeys(recipe.Keys)
			if err != nil {
				t.Fatal(err)
			}
			opts := Options{
				Keys: keys, AllowPrefix: recipe.AllowPrefix,
				AllowUnpinned: recipe.AllowUnpinned, ExplicitV3: recipe.Format == "v3",
			}
			var paths []string
			for _, path := range recipe.Inputs {
				paths = append(paths, filepath.Join(dir, path))
			}
			result, err := verifyPaths(t.Context(), paths, opts, recipe.Finding)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := result.JSON()
			if err != nil {
				t.Fatal(err)
			}
			expected, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "expect.json")))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(changed, bytes.TrimSuffix(expected, []byte{'\n'})) {
				t.Fatalf("disabling %s left the verification result unchanged", recipe.Finding)
			}
			if slices.ContainsFunc(result.Findings, func(f Finding) bool { return f.Code == recipe.Finding }) {
				t.Fatalf("disabled check still produced %s", recipe.Finding)
			}
		})
	}
	for _, code := range targets {
		if !seen[code] {
			t.Errorf("verification check %s has no mutation vector", code)
		}
	}
}

func readMutationRecipe(t *testing.T, dir string) mutationRecipe {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "request.json")))
	if err != nil {
		t.Fatal(err)
	}
	var recipe mutationRecipe
	if err := json.Unmarshal(data, &recipe); err != nil {
		t.Fatal(err)
	}
	return recipe
}
