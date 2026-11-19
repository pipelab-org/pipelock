// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const corpusRoot = "../../../sdk/conformance/testdata/v3"

type mutationRecipe struct {
	Finding       string
	Inputs        []string
	Keys          []string
	AllowPrefix   bool `json:"allow_prefix"`
	AllowUnpinned bool `json:"allow_unpinned"`
	Directory     bool
	ExpectLineage string `json:"expect_lineage"`
	Format        string
}

// TestImplementedFindingTargets detects new checks even when the finding
// registry and mutation cases were not updated alongside the implementation.
func TestImplementedFindingTargets(t *testing.T) {
	corpus, err := os.ReadDir(corpusRoot)
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]bool{
		codeDecisionIndexFull:     t.Run(codeDecisionIndexFull, testDecisionIndexFinding),
		codeLegacyGroupIncomplete: t.Run(codeLegacyGroupIncomplete, testIncompleteLegacyGroup),
	}
	for _, entry := range corpus {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "g") {
			request := readMutationRecipe(t, filepath.Join(corpusRoot, entry.Name()))
			targets[request.Finding] = true
		}
	}
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range files {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || strings.HasSuffix(name, "_generated.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			id, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			code, found := strings.CutPrefix(id.Name, "code")
			if !found || !token.IsExported(code) {
				return true
			}
			for defined := range findingClasses {
				if strings.EqualFold(strings.ReplaceAll(defined, "_", ""), code) {
					if !targets[defined] {
						t.Errorf("%s emits %s without a test target", fset.Position(id.Pos()), defined)
					}
					break
				}
			}
			return true
		})
	}
}

func TestCorpusCheckMutations(t *testing.T) {
	covered := map[string]bool{codeDecisionIndexFull: true, codeLegacyGroupIncomplete: true}
	for _, name := range []string{
		"g01-empty-input",
		"g01-filename-start",
		"g02-signature-bit",
		"g04-clock-regression",
		"g04-data-after-close",
		"g04-heartbeat-gap",
		"g04-lineage-mismatch",
		"g04-tail-after-pin",
		"g04-wrong-expectation",
		"g04-wrong-genesis",
		"g04-wrong-pin",
		"g05-repeat-decision",
		"g06-action-missing-actor",
		"g06-unknown-normalization-profile",
		"g08-wrong-pin",
		"g09-legacy-extended",
		"g09-legacy-head-mismatch",
		"g09-legacy-truncated",
		"g09-unknown-membership",
		"g09-unlisted-legacy",
		"g06-unknown-action-type",
		"g03-empty-optional-member",
		"g09-inventory-mismatch",
		"g09-inventory-absent",
		"g06-higher-action",
		"g04-open-end",
		"g06-unknown-event",
		"g12-fork-order",
		"g04-disconnected",
		"g09-inventory-over-1024-chains",
		"g09-legacy-prefix",
		"g09-legacy-bad-signature",
		"g01-duplicate-keyid",
		"g01-overlong-line",
		"g03-member-order",
		"g04-predecessor-absent",
		"g04-predecessor-truncated",
		"g04-root-fork",
		"g02-small-order-key",
		"g02-identity-r",
		"g02-scalar-at-order",
		"g02-signer-missing",
		"g04-succession-fork",
		"g04-torn-tail",
		"g04-unconfirmed-tail",
		"g06-higher-close",
		"g06-unknown-critical-feature",
		"g01-unsupported-version",
		"g01-unrecognized-input",
		"g01-unclaimed-v3",
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(corpusRoot, name)
			recipe := readMutationRecipe(t, dir)
			covered[recipe.Finding] = true
			keys, err := DecodeKeys(recipe.Keys)
			if err != nil {
				t.Fatal(err)
			}
			opts := Options{
				Keys: keys, AllowPrefix: true, AllowUnpinned: true,
				ExplicitV3: recipe.Format == "v3", Directory: recipe.Directory, ExpectLineage: recipe.ExpectLineage,
			}
			var paths []string
			for _, path := range recipe.Inputs {
				paths = append(paths, filepath.Join(dir, path))
			}
			if opts.Directory {
				paths = []string{dir}
			}
			if name == "g09-unknown-membership" {
				// Accept the missing predecessor so membership is the only
				// remaining reason for refusing this directory.
				opts.AllowPartialHistories = []string{strings.Repeat("3", 32)}
			}
			baseline, err := VerifyPaths(t.Context(), paths, opts)
			if err != nil || !hasFinding(baseline, recipe.Finding) {
				t.Fatalf("target %s did not fire: %+v, %v", recipe.Finding, baseline, err)
			}
			result, err := verifyPaths(t.Context(), paths, opts, recipe.Finding)
			if err != nil {
				t.Fatal(err)
			}
			requireMutation(t, recipe.Finding, baseline, result)
		})
	}
	for code := range findingClasses {
		// The browser reader owns its archive limit.
		if code != codeUseHostVerifier && !covered[code] {
			t.Errorf("finding %s has no check-disable mutation", code)
		}
	}
}

func requireMutation(t *testing.T, code string, baseline, mutant Result) {
	t.Helper()
	if !hasFinding(baseline, code) || hasFinding(mutant, code) {
		t.Fatalf("disabled check %s did not remove its finding: %+v", code, mutant.Findings)
	}
	before, err := baseline.JSON()
	if err != nil {
		t.Fatal(err)
	}
	after, err := mutant.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatalf("disabled check %s did not change the full result", code)
	}
}

func hasFinding(result Result, code string) bool {
	return slices.ContainsFunc(result.Findings, func(f Finding) bool { return f.Code == code })
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
