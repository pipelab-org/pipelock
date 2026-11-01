// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestStructuredJSONGrammarMatchesDLPExtractor(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("[", n) + `"x"` + strings.Repeat("]", n) }
	for _, body := range []string{
		``, ` `, `{}`, `[]`, `42`, `-0`, `01`, `1e999`, `"x"`, `null`, `nul`, `true`, `NaN`,
		`{} {}`, `{"a":1} x`, `{"a":1}` + "\n\t\r ", "\xef\xbb\xbf{}", `[1,2`, `{"a":}`, `[1,]`,
		`{"a":1,}`, `{"a" 1}`, `{1:2}`, `"\ud800"`, "\"\xff\"", `["a"]]`, `]`, `[}`,
		`{"k":"v","k":"w"}`, deep(extractJSONMaxDepth), deep(extractJSONMaxDepth + 1),
		`{"a":` + deep(extractJSONMaxDepth) + `}`,
	} {
		_, _, _, _, _, truncated, dlpErr := extractJSONBodyDLPStrings([]byte(body), BodyScanRequest{})
		_, err := structuredJSONStrings([]byte(body), nil)
		if dlpAccepts, accepts := dlpErr == nil && !truncated, err == nil; dlpAccepts != accepts {
			t.Errorf("%q: DLP extractor accepts=%v (err=%v truncated=%v), structured accepts=%v (err=%v)", body, dlpAccepts, dlpErr, truncated, accepts, err)
		}
	}
}

func TestStructuredJSONStringsSequence(t *testing.T) {
	texts, err := structuredJSONStrings([]byte(`{"k":"v","k":["v",1,true,null,{"":"i"}],"n":"null"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"k", "v", "k", "v", "", "i", "n", "null"}
	if strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Fatalf("texts=%q want %q", texts, want)
	}
}

func TestStructuredResponseAccountReturnsBudget(t *testing.T) {
	cfg := config.Defaults()
	configureStructuredTest(cfg)
	many := structuredDistinctStrings(3000)

	var budget sizeExemptScanBudget
	body, view, release := budget.readStructuredResponse(t.Context(), nil, strings.NewReader(many), cfg, 0)
	release()
	if body != nil || view != nil || budget.inflightBytes.Load() != 0 {
		t.Fatalf("over-budget views admitted or leaked %d bytes", budget.inflightBytes.Load())
	}

	// A small body and its views charge only their retained memory.
	body, view, release = budget.readStructuredResponse(t.Context(), nil, strings.NewReader(`{"data":"garden"}`), cfg, 0)
	if view == nil || view.account == nil || budget.inflightBytes.Load() <= int64(cap(body)) || budget.inflightBytes.Load() >= structuredTestCeiling {
		t.Fatalf("view=%v reserved=%d, want body capacity plus retained views below the ceiling", view, budget.inflightBytes.Load())
	}
	// A rewrite whose rebuilt views exceed what is left fails closed and
	// stays charged to the same admission until release.
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	if result := scanStructuredResponse(t.Context(), sc, cfg, []byte(many), "", view); !result.Failed() || result.Clean {
		t.Fatalf("over-budget rewrite was not refused: %+v", result)
	}
	if !strings.Contains(scanStructuredResponse(t.Context(), sc, cfg, []byte(many), "", view).ScanError, errStructuredViewBudget.Error()) {
		t.Fatal("rewrite refusal does not name the in-flight budget")
	}
	if got := budget.inflightBytes.Load(); got > sizeExemptScanInflightLimit(cfg.ResponseScanning.SizeExemptScanMaxInflightBytes) {
		t.Fatalf("charged %d bytes beyond the in-flight limit", got)
	}
	_ = body
	release()
	release()
	if got := budget.inflightBytes.Load(); got != 0 {
		t.Fatalf("release left %d bytes reserved", got)
	}

	// Larger views draw on the shared budget and return it.
	body, view, release = budget.readStructuredResponse(t.Context(), nil, strings.NewReader(`{"data":"`+strings.Repeat("garden ", 150)+`"}`), cfg, 0)
	if view == nil || budget.inflightBytes.Load() <= structuredTestCeiling {
		t.Fatalf("view=%v reserved=%d, want a shared-budget draw", view != nil, budget.inflightBytes.Load())
	}
	_ = body
	release()
	if got := budget.inflightBytes.Load(); got != 0 {
		t.Fatalf("release left %d bytes reserved", got)
	}
}

type structuredForbiddenReader struct{ t *testing.T }

func (r structuredForbiddenReader) Read([]byte) (int, error) {
	r.t.Error("non-JSON prefix read more upstream bytes")
	return 0, io.EOF
}

func TestStructuredJSONStartRefusesWithoutReservation(t *testing.T) {
	cfg := config.Defaults()
	configureStructuredTest(cfg)
	for _, prefix := range []string{"<html>", " \t\r\n<", "PK\x03\x04", "\xef\xbb\xbf{", "garden", "\x00"} {
		var budget sizeExemptScanBudget
		body, view, release := budget.readStructuredResponse(t.Context(), []byte(prefix), structuredForbiddenReader{t}, cfg, 0)
		release()
		if body != nil || view != nil || budget.inflightBytes.Load() != 0 {
			t.Fatalf("%q: non-JSON start was admitted or reserved", prefix)
		}
	}
	for _, prefix := range []string{"", "   ", "{", "[", `"`, "-", "0", "9", "t", "f", "n", "\n {"} {
		if !structuredJSONStartPossible([]byte(prefix)) {
			t.Errorf("%q: possible JSON start refused", prefix)
		}
	}
}

func TestStructuredAccountNilAndErrors(t *testing.T) {
	var account *structuredResponseAccount
	if err := account.charge(1 << 40); err != nil {
		t.Fatal("nil account must not charge")
	}
	var budget sizeExemptScanBudget
	account = &structuredResponseAccount{budget: &budget, limit: 10}
	if err := account.charge(4); err != nil || account.reserved != 4 || budget.inflightBytes.Load() != 4 {
		t.Fatal("charge did not reserve the retained bytes")
	}
	if err := account.charge(11); !errors.Is(err, errStructuredViewBudget) || budget.inflightBytes.Load() != 4 {
		t.Fatal("charge beyond the limit was not refused cleanly")
	}
	if _, err := structuredJSONStrings([]byte(`["a","b"]`), &structuredResponseAccount{budget: &budget, limit: 1}); !errors.Is(err, errStructuredViewBudget) {
		t.Fatalf("string extraction ignored its budget: %v", err)
	}
}

func TestStructuredResponseLeadingEmptyJoin(t *testing.T) {
	view, err := extractStructuredResponse([]byte(`["","garden","orchard",""]`))
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range view.Parts {
		if part.Role == "first_occurrence_join" {
			if want := "\ngarden\norchard"; part.Text != want {
				t.Fatalf("first-occurrence join = %q, want %q", part.Text, want)
			}
			return
		}
	}
	t.Fatal("missing first-occurrence join")
}
