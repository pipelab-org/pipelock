// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestPayloadCanonicalStringsAndArrays(t *testing.T) {
	for _, tc := range []struct {
		wire string
		ok   bool
	}{
		{`{"a":["é","\b\f\n\r\t","\u0000",true,false,-1]}`, true},
		{"{\"a\":\"\x00\"}", false},
		{"{\"a\":\"\xff\"}", false},
		{`{"a":["\u000a"]}`, false},
		{`{"a":["\u0041"]}`, false},
		{`{"a":["\u000A"]}`, false},
		{`{"a":["\/"]}`, false},
		{`{"a":[nul]}`, false},
		{`{"a":[tru]}`, false},
		{`{"a":[123456789012345678]}`, false},
	} {
		parser := payloadParser{data: []byte(tc.wire)}
		if _, ok := parser.object(1); (ok && parser.pos == len(tc.wire)) != tc.ok {
			t.Errorf("canonical payload %q: parsed %t, position %d", tc.wire, ok, parser.pos)
		}
	}
}

func TestDecisionOutcomesAndRefusals(t *testing.T) {
	first, second := int64(1), int64(2)
	intent := Action{
		ActionID: "example", Phase: "intent", Verdict: "allow", Attempt: &first,
		EffectBoundary: "upstream_send", EffectRelation: "before", Target: "api.vendor.example",
	}
	outcome := func(class, relation string) Action {
		result := intent
		result.Phase, result.OutcomeClass, result.EffectRelation = "outcome", class, relation
		return result
	}
	before := outcome("failed_before_attempt", "not_attempted")
	after := outcome("failed_after_attempt", "after")
	unknown := outcome("attempt_unknown", "unknown")
	refused := outcome("not_released", "not_attempted")
	refused.Verdict = "block"
	retry := intent
	retry.Attempt = &second
	changed := retry
	changed.Target = "other.vendor.example"
	wrongVerdict := after
	wrongVerdict.Verdict = "warn"
	hold := Action{
		Phase: "hold", Verdict: "ask", EffectBoundary: "approval_prompt", EffectRelation: "before",
		Hold: &Hold{ID: "example", Policy: "example"}, Ask: &Ask{Channel: "approval_api", Observed: true},
	}
	resolution := hold
	resolution.Phase, resolution.EffectRelation = "resolution", "after"
	for _, tc := range []struct {
		name    string
		actions []Action
		state   string
	}{
		{"definite refusal", []Action{refused}, "not_released"},
		{"before attempt", []Action{intent, before}, "failed"},
		{"after attempt", []Action{intent, after}, "failed"},
		{"unknown attempt", []Action{intent, unknown}, "outcome_unknown"},
		{"retry after refusal", []Action{refused, retry}, "outcome_unknown"},
		{"retry after release", []Action{intent, after, retry}, ""},
		{"retry changed effect", []Action{refused, changed}, ""},
		{"outcome changed verdict", []Action{intent, wrongVerdict}, ""},
		{"attempt skipped", []Action{retry}, ""},
		{"approval step-up", []Action{hold, resolution}, "stepped_up"},
		{"repeated resolution", []Action{hold, resolution, resolution}, ""},
		{"resolution without hold", []Action{resolution}, ""},
		{"repeated hold", []Action{hold, hold}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := AppraisePiece(tc.actions, make([]bool, len(tc.actions)), false)
			if got != tc.state || ok != (tc.state != "") {
				t.Fatalf("decision = %q, %t, want %q", got, ok, tc.state)
			}
		})
	}
}

func TestVerifierRefusalVectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit int
	}{
		{"g01-extra-outer-member", 1},
		{"g01-outer-whitespace", 1},
		{"g01-second-payload", 1},
		{"g01-signature-entry-suffix", 1},
		{"g01-signature-keyid-hex", 1},
		{"g01-too-many-signatures", 1},
		{"g01-unsupported-payload", 3},
		{"g01-urlsafe-signature", 1},
		{"g03-escaped-printable", 1},
		{"g03-escaped-short-control", 1},
		{"g03-excess-depth", 1},
		{"g03-invalid-utf8", 1},
		{"g03-literal-control", 1},
		{"g03-uppercase-hex-control", 1},
		{"g04-spliced-stream", 1},
		{"g06-action-writer-config", 1},
		{"g06-caller-verified-missing-identity", 1},
		{"g06-nested-approval-ask-unobserved", 1},
		{"g06-nested-caller-none-with-issuer", 1},
		{"g06-nested-coverage-unsorted", 1},
		{"g06-nested-empty-optional-contract", 1},
		{"g06-nested-hold-no-policy", 1},
		{"g06-nested-incorrect-close-count", 1},
		{"g06-nested-previous-and-cutover", 1},
		{"g06-nested-redaction-classes-repeated", 1},
		{"g06-nested-resolution-with-parent", 1},
		{"g06-target-excess-bytes", 1},
		{"g06-writer-excess-bytes", 1},
		{"g06-unknown-close-reason", 3},
		{"g06-unknown-signer-algorithm", 3},
		{"g07-operational-logs-only", 3},
		{"g09-empty-inventory-count", 1},
		{"g09-invalid-inventory-journal", 1},
		{"g09-invalid-inventory-version", 1},
		{"g09-invalid-legacy", 1},
		{"g09-inventory-trailing-data", 1},
		{"g12-contested-opener-order", 1},
		{"g12-damaged-unpinned-inventory", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(corpusRoot, tc.name)
			recipe := readMutationRecipe(t, dir)
			keys, err := DecodeKeys(recipe.Keys)
			if err != nil {
				t.Fatal(err)
			}
			paths := make([]string, 0, len(recipe.Inputs))
			for _, name := range recipe.Inputs {
				paths = append(paths, filepath.Join(dir, name))
			}
			if recipe.Directory {
				paths = []string{dir}
			}
			opts := Options{Keys: keys, Directory: recipe.Directory, AllowUnpinned: recipe.AllowUnpinned}
			result, err := VerifyPaths(t.Context(), paths, opts)
			if err != nil || result.ExitCode != tc.exit || !hasFinding(result, recipe.Finding) {
				t.Fatalf("refusal = %q, exit %d, findings %+v, error %v", result.Verdict, result.ExitCode, result.Findings, err)
			}
		})
	}
}

func TestExportDSSEMatchesCorpus(t *testing.T) {
	dir := filepath.Join(corpusRoot, "g11-dsse-export")
	recipe := readMutationRecipe(t, dir)
	storage, err := os.ReadFile(filepath.Clean(filepath.Join(dir, recipe.Inputs[0])))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "export.dsse.jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	for line := range bytes.SplitAfterSeq(storage, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		envelope, code := ExportDSSE(line)
		if code != "" {
			t.Fatalf("export finding = %q, want none", code)
		}
		got = append(got, envelope...)
		got = append(got, '\n')
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("exported DSSE = %s, want %s", got, want)
	}
}

func TestExportDSSEPreservesSignatureOrder(t *testing.T) {
	dir := filepath.Join(corpusRoot, "g02-ignore-extra-signature")
	recipe := readMutationRecipe(t, dir)
	storage, err := os.ReadFile(filepath.Clean(filepath.Join(dir, recipe.Inputs[0])))
	if err != nil {
		t.Fatal(err)
	}
	line := storage[:bytes.IndexByte(storage, '\n')+1]
	var input, output struct {
		Signatures []struct {
			KeyID string
			Sig   string
		}
	}
	if err := json.Unmarshal(line, &input); err != nil {
		t.Fatal(err)
	}
	envelope, code := ExportDSSE(line)
	if code != "" {
		t.Fatalf("export finding = %q, want none", code)
	}
	if err := json.Unmarshal(envelope, &output); err != nil {
		t.Fatal(err)
	}
	if len(input.Signatures) != 2 || !slices.Equal(input.Signatures, output.Signatures) {
		t.Fatalf("exported signatures = %+v, want the original ordered pair %+v", output.Signatures, input.Signatures)
	}
}
