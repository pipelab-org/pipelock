// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"path/filepath"
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

func TestWireRefusalVectors(t *testing.T) {
	for _, name := range []string{
		"g03-escaped-printable",
		"g03-escaped-short-control",
		"g03-excess-depth",
		"g03-invalid-utf8",
		"g03-literal-control",
		"g03-uppercase-hex-control",
		"g06-action-writer-config",
		"g06-caller-verified-missing-identity",
		"g06-nested-approval-ask-unobserved",
		"g06-nested-caller-none-with-issuer",
		"g06-nested-coverage-unsorted",
		"g06-nested-empty-optional-contract",
		"g06-nested-hold-no-policy",
		"g06-nested-incorrect-close-count",
		"g06-nested-previous-and-cutover",
		"g06-nested-redaction-classes-repeated",
		"g06-nested-resolution-with-parent",
		"g06-target-excess-bytes",
		"g06-writer-excess-bytes",
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(corpusRoot, name)
			recipe := readMutationRecipe(t, dir)
			keys, err := DecodeKeys(recipe.Keys)
			if err != nil {
				t.Fatal(err)
			}
			paths := make([]string, 0, len(recipe.Inputs))
			for _, name := range recipe.Inputs {
				paths = append(paths, filepath.Join(dir, name))
			}
			result, err := VerifyPaths(t.Context(), paths, Options{Keys: keys})
			if err != nil || result.ExitCode != 1 || !hasFinding(result, recipe.Finding) {
				t.Fatalf("refusal = %q, exit %d, findings %+v, error %v", result.Verdict, result.ExitCode, result.Findings, err)
			}
		})
	}
}
