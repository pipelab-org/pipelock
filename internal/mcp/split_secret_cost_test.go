// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// splitSecretToolCall builds a tools/call whose argument values are n copies
// of value, except the last value is padded so the argument text totals total
// bytes when total > 0. total 0 keeps every argument at len(value).
func splitSecretToolCall(n int, value string, total int) []byte {
	fields := make([]string, 0, n)
	if total <= 0 {
		for i := 0; i < n; i++ {
			fields = append(fields, fmt.Sprintf(`"f%02d":%q`, i, value))
		}
	} else {
		each := total / n
		rem := total - each*n
		for i := 0; i < n; i++ {
			size := each
			if i == n-1 {
				size += rem
			}
			if size < 1 {
				size = 1
			}
			fields = append(fields, fmt.Sprintf(`"f%02d":"%s"`, i, strings.Repeat("x", size)))
		}
	}
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{` + strings.Join(fields, ",") + `}}}`)
}

// orderedPairWork is the bytes the unmodified pairwise loop would hand to
// text DLP: both orders of every non-empty extracted pair.
func orderedPairWork(raw []byte) int64 {
	vals := jsonrpc.ExtractStringsFromJSONResult(raw).Strings
	var used int64
	for i := range vals {
		if vals[i] == "" {
			continue
		}
		for j := i + 1; j < len(vals); j++ {
			if vals[j] == "" {
				continue
			}
			used += 2 * int64(len(vals[i])+len(vals[j]))
		}
	}
	return used
}

func assertSplitWorkRefusal(t *testing.T, verdict InputVerdict) {
	t.Helper()
	if verdict.Clean || verdict.Action != config.ActionBlock || verdict.Error != "" {
		t.Fatalf("verdict clean=%v action=%s err=%q, want block with empty error", verdict.Clean, verdict.Action, verdict.Error)
	}
	if len(verdict.Matches) == 0 || verdict.Matches[0].PatternName != uninspectableSplitSecretFieldsReason || verdict.Matches[0].Severity != config.SeverityCritical {
		t.Fatalf("matches=%+v, want leading %q", verdict.Matches, uninspectableSplitSecretFieldsReason)
	}
	layer, pattern, severity := contentScanAttribution(verdict)
	if layer != mcpReceiptLayerInput || pattern != uninspectableSplitSecretFieldsReason || severity != config.SeverityCritical {
		t.Fatalf("receipt layer=%q pattern=%q severity=%q", layer, pattern, severity)
	}
	if !preRedactionBlock(verdict, config.ActionWarn) {
		t.Fatal("work-budget refusal must keep the pre-redaction block")
	}
}

func TestSplitSecretWorkBudgetRefusesWidePayload(t *testing.T) {
	sc := testInputScanner(t)
	// Same total argument bytes as one field. 56 and 61 arguments stay inside
	// the 64-string cap and, without a work budget, run the full pair scan.
	for _, n := range []int{56, 61} {
		t.Run(fmt.Sprintf("%d-fields", n), func(t *testing.T) {
			body := splitSecretToolCall(n, "", 256*1024)
			work := orderedPairWork(body)
			if work <= maxPairwiseSplitWorkBytes {
				t.Fatalf("pair work %d is inside budget %d; this fixture no longer exceeds it", work, maxPairwiseSplitWorkBytes)
			}
			verdict := ScanRequest(t.Context(), body, sc, config.ActionWarn, config.ActionWarn)
			assertSplitWorkRefusal(t, verdict)
		})
	}
}

func TestSplitSecretWorkBudgetAllowsOrdinaryCalls(t *testing.T) {
	sc := testInputScanner(t)
	cases := []struct {
		name string
		body []byte
	}{
		{"one 256KiB field", splitSecretToolCall(1, "", 256*1024)},
		{"40 short fields", splitSecretToolCall(40, "short-note", 0)},
		{"20 medium fields", splitSecretToolCall(20, strings.Repeat("m", 256), 0)},
		{"20 one-kibibyte fields", splitSecretToolCall(20, strings.Repeat("m", 1024), 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			work := orderedPairWork(tc.body)
			if work > maxPairwiseSplitWorkBytes {
				t.Fatalf("pair work %d exceeds budget %d", work, maxPairwiseSplitWorkBytes)
			}
			verdict := ScanRequest(t.Context(), tc.body, sc, config.ActionBlock, config.ActionBlock)
			if !verdict.Clean || verdict.Action != "" || verdict.Error != "" || len(verdict.Matches) != 0 {
				t.Fatalf("ordinary call refused: clean=%v action=%s err=%q matches=%+v", verdict.Clean, verdict.Action, verdict.Error, verdict.Matches)
			}
		})
	}
}

func TestSplitSecretFindingPrecedesWorkBudget(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:     "pair-anchor",
		Regex:    `^left-half-right-half$`,
		Severity: config.SeverityCritical,
	})
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	filler := strings.Repeat("x", 64*1024)
	var fillers, late []string
	for i := 0; i < 8; i++ {
		field := fmt.Sprintf(`"f%02d":"%s"`, i, filler)
		fillers = append(fillers, field)
		late = append(late, field)
	}
	late = append(late, `"z_left":"left-half-"`, `"z_right":"right-half"`)
	wrap := func(fields []string) []byte {
		return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{` + strings.Join(fields, ",") + `}}}`)
	}

	t.Run("finding already made", func(t *testing.T) {
		// The id and the method are the first strings the extractor yields, so
		// their pair is scanned before any large argument is charged.
		prefix := testSecretPrefix
		suffix := "api03-" + strings.Repeat("B", 20)
		body := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":%q,"params":{"name":"fetch","arguments":{`+strings.Join(fillers, ",")+`}}}`, prefix, suffix))
		if orderedPairWork(body) <= maxPairwiseSplitWorkBytes {
			t.Fatalf("fixture work %d does not exhaust the budget", orderedPairWork(body))
		}
		verdict := ScanRequest(t.Context(), body, sc, config.ActionWarn, config.ActionWarn)
		if verdict.Clean || verdict.Error != "" || len(verdict.Matches) == 0 || verdict.Matches[0].PatternName != "Anthropic API Key" {
			t.Fatalf("finding lost: %+v", verdict)
		}
		for _, match := range verdict.Matches {
			if match.PatternName == uninspectableSplitSecretFieldsReason {
				t.Fatalf("budget stop replaced a finding the pair scan had already made: %+v", verdict.Matches)
			}
		}
	})

	t.Run("budget stops before the pair", func(t *testing.T) {
		body := wrap(late)
		if orderedPairWork(body) <= maxPairwiseSplitWorkBytes {
			t.Fatalf("fixture work %d does not exhaust the budget", orderedPairWork(body))
		}
		verdict := ScanRequest(t.Context(), body, sc, config.ActionWarn, config.ActionWarn)
		assertSplitWorkRefusal(t, verdict)
		for _, match := range verdict.Matches {
			if match.PatternName == "pair-anchor" {
				t.Fatalf("pair past the budget was still scanned: %+v", verdict.Matches)
			}
		}
	})

	t.Run("earlier match kept", func(t *testing.T) {
		body := wrap(late)
		raw := jsonrpc.ExtractStringsFromJSONResult(body)
		prior := scanner.TextDLPResult{
			Clean:   true,
			Matches: []scanner.TextDLPMatch{{PatternName: "earlier-note", Severity: config.SeverityHigh}},
		}
		result := scanSplitSecret(t.Context(), body, strings.Join(raw.Strings, "\n"), sc, prior)
		if result.Clean || len(result.Matches) < 2 || result.Matches[0].PatternName != uninspectableSplitSecretFieldsReason {
			t.Fatalf("budget stop dropped or outranked the refusal: %+v", result)
		}
		kept := false
		for _, match := range result.Matches[1:] {
			if match.PatternName == "earlier-note" && match.Severity == config.SeverityHigh {
				kept = true
			}
		}
		if !kept {
			t.Fatalf("earlier match lost: %+v", result.Matches)
		}
	})
}

// referenceScanSplitSecret is the pairwise loop without a work budget.
// Inputs inside the budget must match it match for match.
func referenceScanSplitSecret(ctx context.Context, raw json.RawMessage, joined string, sc *scanner.Scanner, result scanner.TextDLPResult) scanner.TextDLPResult {
	if !result.Clean && !scanner.OnlyInformational(result.Matches) {
		return result
	}
	extracted := jsonrpc.ExtractStringsFromJSONResult(raw)
	if extracted.Truncated {
		return scanner.TextDLPResult{
			Clean: false,
			Matches: []scanner.TextDLPMatch{{
				PatternName: uninspectableJSONDepthReason,
				Severity:    config.SeverityCritical,
			}},
		}
	}
	vals := extracted.Strings
	cardAtoms := extract.AllStringsFromJSONResult(raw).Atoms
	if len(vals) <= 1 {
		return result
	}
	concat := strings.Join(vals, "")
	if concat != joined {
		if r := sc.ScanTextForDLPWithTypedCardView(ctx, concat, extract.JoinCardAtoms(cardAtoms, "")); r.Err() != nil || len(r.Matches) > 0 {
			result = mergeInputDLP(result, r)
			if !r.Clean {
				return result
			}
		}
	}
	if len(vals) > maxPairwiseSplitFields {
		return scanner.TextDLPResult{
			Clean: false,
			Matches: []scanner.TextDLPMatch{{
				PatternName: uninspectableSplitSecretFieldsReason,
				Severity:    config.SeverityCritical,
			}},
		}
	}
	for i := 0; i < len(vals); i++ {
		if len(vals[i]) == 0 {
			continue
		}
		for j := i + 1; j < len(vals); j++ {
			if len(vals[j]) == 0 {
				continue
			}
			if r := sc.ScanTextForDLPWithTypedCardView(ctx, vals[i]+vals[j], ""); r.Err() != nil || len(r.Matches) > 0 {
				result = mergeInputDLP(result, r)
				if !r.Clean {
					return result
				}
			}
			if r := sc.ScanTextForDLPWithTypedCardView(ctx, vals[j]+vals[i], ""); r.Err() != nil || len(r.Matches) > 0 {
				result = mergeInputDLP(result, r)
				if !r.Clean {
					return result
				}
			}
		}
	}
	return result
}

func matchView(matches []scanner.TextDLPMatch) []string {
	out := make([]string, len(matches))
	for i, match := range matches {
		span := match.Span()
		out[i] = fmt.Sprintf("%s|%s|%d|%d|%s", match.PatternName, match.Severity, span.ByteStart, span.ByteEnd, span.ViewLabel)
	}
	return out
}

func TestSplitSecretPairBudgetMatchesFullScan(t *testing.T) {
	prefix := testSecretPrefix
	suffix := "api03-" + strings.Repeat("A", 20)
	customCfg := func() *config.Config {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
			Name:     "pair-anchor",
			Regex:    `^left-half-right-half$`,
			Severity: config.SeverityCritical,
		})
		return cfg
	}
	cases := []struct {
		name    string
		cfg     func() *config.Config
		fields  string
		wantAny string
	}{
		{
			name:    "split credential left then right",
			fields:  fmt.Sprintf(`"a_left":%q,"z_right":%q`, prefix, suffix),
			wantAny: "Anthropic API Key",
		},
		{
			name:    "split credential right then left",
			fields:  fmt.Sprintf(`"a_right":%q,"z_left":%q`, suffix, prefix),
			wantAny: "Anthropic API Key",
		},
		{
			name:    "split credential around noise",
			fields:  fmt.Sprintf(`"a_left":%q,"m_noise":"ordinary note","z_right":%q`, prefix, suffix),
			wantAny: "Anthropic API Key",
		},
		{
			name:    "anchored custom pattern",
			cfg:     customCfg,
			fields:  `"a_left":"left-half-","m_noise":"ordinary note","z_right":"right-half"`,
			wantAny: "pair-anchor",
		},
		{
			name:    "anchored custom pattern reverse order",
			cfg:     customCfg,
			fields:  `"a_right":"right-half","m_noise":"ordinary note","z_left":"left-half-"`,
			wantAny: "pair-anchor",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			if tc.cfg != nil {
				cfg = tc.cfg()
			}
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{` + tc.fields + `}}}`)
			if orderedPairWork(body) > maxPairwiseSplitWorkBytes {
				t.Fatalf("parity fixture exceeds the budget (%d)", orderedPairWork(body))
			}
			joined := strings.Join(jsonrpc.ExtractStringsFromJSONResult(body).Strings, "\n")
			clean := scanner.TextDLPResult{Clean: true}
			got := scanSplitSecret(t.Context(), body, joined, sc, clean)
			want := referenceScanSplitSecret(t.Context(), body, joined, sc, clean)
			if got.Clean != want.Clean || got.Incomplete != want.Incomplete || !slices.Equal(matchView(got.Matches), matchView(want.Matches)) {
				t.Fatalf("budgeted scan\n got clean=%v incomplete=%v %v\nwant clean=%v incomplete=%v %v", got.Clean, got.Incomplete, matchView(got.Matches), want.Clean, want.Incomplete, matchView(want.Matches))
			}
			if got.Clean || !strings.Contains(strings.Join(matchView(got.Matches), "\n"), tc.wantAny) {
				t.Fatalf("missing %s: %+v", tc.wantAny, got.Matches)
			}
			verdict := ScanRequest(t.Context(), body, sc, config.ActionBlock, config.ActionBlock)
			if verdict.Clean || verdict.Error != "" {
				t.Fatalf("outbound verdict lost the pair: %+v", verdict)
			}
			found := false
			for _, match := range verdict.Matches {
				if match.PatternName == tc.wantAny {
					found = true
				}
			}
			if !found {
				t.Fatalf("outbound matches lack %s: %+v", tc.wantAny, verdict.Matches)
			}
		})
	}
}
