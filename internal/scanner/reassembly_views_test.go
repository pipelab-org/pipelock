// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestViewSelectionTextPaths(t *testing.T) {
	body := reassemblyBang(hex.EncodeToString([]byte(inspectionLimitAWSKey())))
	jsonText := strings.ReplaceAll(body, "!", `\u0021`)
	percent := url.PathEscape(jsonText)
	entity := strings.ReplaceAll(percent, "%", "&#37;")
	for _, tc := range []struct {
		name, input string
		want        []string
	}{
		{"input", body, []string{body}},
		{"url", url.QueryEscape(body), []string{url.QueryEscape(body), body}},
		{"html", strings.ReplaceAll(body, "!", "&#33;"), []string{strings.ReplaceAll(body, "!", "&#33;"), body}},
		{"json", jsonText, []string{jsonText, body}},
		{"mixed", entity, []string{entity, percent, jsonText, body}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memo := &decodingMemo{reassemblyPlan: reassemblyTestPlan(t), reassemblyDeferred: true}
			decoded, complete := decodeEncodingsBudgetMode(tc.input, true, 0, false)
			if !complete {
				t.Fatal("control decode incomplete")
			}
			memo.reassemblyObserveDecoded(tc.input, decoded)
			for _, want := range tc.want {
				if !slices.Contains(memo.reassemblyPending, want) {
					t.Errorf("text path absent: %q", want)
				}
			}
			for _, got := range memo.reassemblyPending {
				if !memo.reassemblyViewKinds[got].textual() {
					continue
				}
				if !slices.Contains(tc.want, got) {
					t.Errorf("unproved view admitted: %q", got)
				}
			}
			result := finishAssembled(TextDLPResult{Clean: true}, memo)
			if !slices.Contains(matchNames(result.Matches), "AWS Access ID") || HasInspectionLimit(result.Matches) {
				t.Fatal("text path lost detection", result)
			}
		})
	}
}

func TestViewSelectionRejectsBinaryAncestry(t *testing.T) {
	body := reassemblyBang(hex.EncodeToString([]byte(inspectionLimitAWSKey())))
	escaped := strings.ReplaceAll(body, "!", "&#33;")
	for _, tc := range []struct{ name, input string }{
		{"base64", base64.StdEncoding.EncodeToString([]byte(escaped))},
		{"hex", hex.EncodeToString([]byte(escaped))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memo := &decodingMemo{reassemblyPlan: reassemblyTestPlan(t), reassemblyDeferred: true}
			decoded, complete := decodeEncodingsBudgetMode(tc.input, true, 0, false)
			if !complete || !slices.ContainsFunc(decoded, func(v decodedResult) bool { return v.text == body }) {
				t.Fatal("binary then text control did not decode")
			}
			memo.reassemblyObserveDecoded(tc.input, decoded)
			for _, got := range memo.reassemblyPending {
				if got != tc.input && memo.reassemblyViewKinds[got].textual() {
					t.Fatal("binary descendant gained textual eligibility")
				}
			}
		})
	}
	// Last-edge labels are descriptive, not authority to register unrelated bytes.
	memo := &decodingMemo{reassemblyPlan: reassemblyTestPlan(t), reassemblyDeferred: true}
	memo.reassemblyObserveDecoded("ordinary &amp; report", []decodedResult{{text: body, encoding: encodingHTML}, {text: body, encoding: encodingURL}, {text: body, encoding: encodingJSONUnicode}})
	if memo.reassemblyViewKinds[body].textual() {
		t.Fatal("unrelated labelled view admitted")
	}
}

func TestViewSelectionSharedCache(t *testing.T) {
	p := reassemblyTestPlan(t)
	body := reassemblyBang(hex.EncodeToString([]byte(inspectionLimitAWSKey())))
	source := strings.ReplaceAll(body, "!", "&#33;")
	ctx, release := WithSharedDecodes(context.Background())
	defer release()
	for round := range 2 {
		memo := &decodingMemo{reassemblyPlan: p, reassemblyDeferred: true, shared: sharedDecodesFrom(ctx)}
		memo.decode(source, true)
		var textual []string
		for _, view := range memo.reassemblyPending {
			if memo.reassemblyViewKinds[view].textual() {
				textual = append(textual, view)
			}
		}
		if !slices.Equal(textual, []string{source, body}) {
			t.Fatalf("round %d: shared view selection %q", round, memo.reassemblyPending)
		}
		result := finishAssembled(TextDLPResult{Clean: true}, memo)
		if !slices.Contains(matchNames(result.Matches), "AWS Access ID") || HasInspectionLimit(result.Matches) {
			t.Fatal("shared text path lost detection")
		}
	}
}

func TestViewSelectionHistoricalNestedDefault(t *testing.T) {
	key := inspectionLimitAWSKey()
	inner := hex.EncodeToString([]byte(key))
	source := base64.StdEncoding.EncodeToString([]byte(inner))
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	defer sc.Close()
	for _, inbound := range []bool{false, true} {
		ctx := context.Background()
		if inbound {
			ctx = WithInboundDirection(ctx)
		}
		result := sc.ScanTextForDLP(ctx, source)
		if !slices.Contains(matchNames(result.Matches), "AWS Access ID") || HasInspectionLimit(result.Matches) {
			t.Fatal("historical nested decode lost detection", inbound, result)
		}
	}
}

func TestViewSelectionContiguousHex(t *testing.T) {
	digest := strings.Repeat("3", 64)
	decoded, complete := decodeEncodingsBudgetMode(digest, true, 0, false)
	if !complete || !slices.ContainsFunc(decoded, func(v decodedResult) bool { return v.encoding == encodingHex && v.text == strings.Repeat("3", 32) }) {
		t.Fatal("contiguous decoder declined repeated digest")
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Configured probe", Regex: `[0-9]{16}`, Severity: config.SeverityHigh})
	sc := MustNew(cfg)
	defer sc.Close()
	result := sc.ScanTextForDLP(context.Background(), "first: "+strings.Repeat("1", 16)+"\nsha256: "+digest+"\n")
	target := sha256.Sum256([]byte(strings.Repeat("3", 16)))
	if !slices.ContainsFunc(result.Matches, func(m TextDLPMatch) bool {
		return m.PatternName == "Configured probe" && m.hasValueIdentity && m.valueIdentity == target
	}) {
		t.Fatal("genuine contiguous decode lost")
	}
}

func TestViewSelectionGraphOrder(t *testing.T) {
	body := reassemblyBang(hex.EncodeToString([]byte(inspectionLimitAWSKey())))
	input := `\u0021%21` + body
	jsonFirst := "!%21" + body
	urlFirst := `\u0021!` + body
	combined := "!!" + body
	allowed := []string{jsonFirst, urlFirst, combined}
	decoded, complete := decodeEncodingsBudgetMode(input, true, 0, false)
	if !complete {
		t.Fatal("order witness incomplete")
	}
	expected := []string{input}
	for _, view := range decoded {
		if slices.Contains(allowed, view.text) && !slices.Contains(expected, view.text) {
			expected = append(expected, view.text)
		}
	}
	if len(expected) != 4 || expected[1] != jsonFirst || expected[2] != urlFirst {
		t.Fatal("order witness did not distinguish graph order", expected)
	}
	memo := &decodingMemo{reassemblyPlan: reassemblyTestPlan(t), reassemblyDeferred: true}
	memo.reassemblyObserveDecoded(input, decoded)
	var textual []string
	for _, view := range memo.reassemblyPending {
		if memo.reassemblyViewKinds[view].textual() {
			textual = append(textual, view)
		}
	}
	if !slices.Equal(textual, expected) {
		t.Fatal("text selection reordered graph views", memo.reassemblyPending, expected)
	}
}
