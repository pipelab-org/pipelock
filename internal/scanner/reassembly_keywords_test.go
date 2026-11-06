// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyKeywordSourceContext(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Labeled record", Regex: `[0-9]{16}`, Severity: config.SeverityHigh, Keywords: []string{"lookup"}}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name, body string
	}{
		{"source", reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5000)))) + " lookup " + reassemblyBang(hex.EncodeToString([]byte("3333333333333333")))},
		{"decoded", reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5000) + " lookup 3333333333333333")))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			production := sc.ScanTextForDLP(t.Context(), tc.body)
			productionFound := false
			for _, match := range production.Matches {
				if match.PatternName == "Labeled record" {
					productionFound = true
					if !match.RequiresKeywordContext() {
						t.Fatal("production finding lost keyword redaction obligation")
					}
				}
			}
			if !productionFound {
				t.Fatal("production scan lost the labeled record")
			}
			result := reassemblyTerminal(sc.reassemblyPlan, tc.body, &assembledBudget{})
			for _, match := range result.findings {
				if match.PatternName == "Labeled record" {
					if !match.RequiresKeywordContext() {
						t.Fatal("terminal finding lost keyword redaction obligation")
					}
					return
				}
			}
			t.Fatalf("terminal lost nearby keyword: incomplete=%v findings=%+v", result.incomplete, result.findings)
		})
	}
}

func TestReassemblyKeywordTrackedViews(t *testing.T) {
	body := reassemblyBang(hex.EncodeToString([]byte(inspectionLimitAWSKey())))
	input := strings.ReplaceAll(body, "!", `\u0021`)
	for _, cached := range []bool{false, true} {
		memo := &decodingMemo{keywordMode: true, reassemblyPlan: reassemblyTestPlan(t), reassemblyDeferred: true}
		memo.decode(input, true)
		if cached {
			memo.reassemblyPending = nil
			memo.reassemblySeen = nil
			memo.reassemblyTextRoots = nil
			memo.decode(input, true)
		}
		found := false
		for _, view := range memo.reassemblyPending {
			found = found || view == body
		}
		if !found {
			t.Fatalf("keyword tracked decoder lost terminal text view; cached=%v", cached)
		}
	}
}

func TestReassemblyKeywordSourceWindows(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Labeled record", Regex: `[0-9]{30}`, Severity: config.SeverityHigh, Keywords: []string{"~~~"}, KeywordWindow: new(10)}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	prefix := reassemblyEncodings(strings.Repeat("x", 5040))
	for codec, value := range reassemblyEncodings(strings.Repeat("3", 30)) {
		for phase := range value.quantum {
			for _, tc := range []struct {
				name, before, after string
				want                bool
			}{
				{"before edge", "~~~" + strings.Repeat(" ", 7), "", true},
				{"before outside", "~~~" + strings.Repeat(" ", 8), "", false},
				{"after edge", "", strings.Repeat(" ", 7) + "~~~", true},
				{"after outside", "", strings.Repeat(" ", 8) + "~~~", false},
				{"absent", "", "", false},
			} {
				t.Run(value.name+"/"+string(rune('0'+phase))+"/"+tc.name, func(t *testing.T) {
					body := strings.Repeat(string(reassemblyCodecs[codec].alphabet[0])+"!", phase) + reassemblyBang(prefix[codec].text) + tc.before + reassemblyBang(value.text) + tc.after
					result := reassemblyTerminal(sc.reassemblyPlan, body, &assembledBudget{})
					got := len(result.findings) > 0
					if got != tc.want || result.incomplete {
						t.Fatalf("found=%v want=%v incomplete=%v", got, tc.want, result.incomplete)
					}
				})
			}
		}
	}
}

func TestReassemblyKeywordContextBudget(t *testing.T) {
	sc := keywordScanner(t, []string{"lookup"}, 50)
	defer sc.Close()
	body := "lookup " + reassemblyBang(hex.EncodeToString([]byte("3333333333333333")))
	memo := &decodingMemo{keywordBudget: &keywordWorkBudget{used: maxDecodeTotalBytes}}
	result := reassemblyTerminal(sc.reassemblyPlan, body, &assembledBudget{memo: memo})
	if !result.incomplete || !memo.inspectionIncomplete() || len(result.findings) != 0 {
		t.Fatalf("unavailable keyword context failed open: %+v", result)
	}
}

func TestReassemblyKeywordCandidateContinuation(t *testing.T) {
	sc := keywordScanner(t, []string{"lookup"}, 10)
	defer sc.Close()
	for _, plain := range []string{
		strings.Repeat("x", 5000) + "3333333333333333" + strings.Repeat(" ", 50) + "lookup 3333333333333333",
		strings.Repeat("x", 5000) + "3333333333333333" + strings.Repeat(" ", 50) + "LOOKUP 3333333333333333",
	} {
		result := reassemblyTerminal(sc.reassemblyPlan, reassemblyBang(hex.EncodeToString([]byte(plain))), &assembledBudget{})
		if len(result.findings) != 1 || !result.findings[0].RequiresKeywordContext() || result.incomplete {
			t.Fatalf("rejected decoy hid qualified candidate: %+v", result)
		}
	}
}

func TestReassemblyKeywordNestedSource(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Labeled secret", Regex: `SECRET[0-9]{16}`, Severity: config.SeverityHigh, Keywords: []string{"lookup"}}}
	sc := MustNew(cfg)
	defer sc.Close()
	prefix := reassemblyBang(reassemblyEncodings(strings.Repeat("x", 5040))[1].text)
	suffix := reassemblyBang(reassemblyEncodings("SECRET3333333333333333")[1].text)
	body := hex.EncodeToString([]byte(prefix)) + " lookup " + hex.EncodeToString([]byte(suffix))
	memo := &decodingMemo{keywordMode: true, keywordUnit: body, keywordInput: body}
	result := reassemblyTerminal(sc.reassemblyPlan, body, &assembledBudget{memo: memo})
	if len(result.findings) == 0 || result.incomplete {
		t.Fatalf("nested RFC source context lost: %+v", result)
	}
}

func TestReassemblyKeywordExactNormalization(t *testing.T) {
	sc := keywordScanner(t, []string{"lookup"}, 10)
	defer sc.Close()
	for _, before := range []string{"lookup ", "ＬＯＯＫＵＰ ", "\xff lookup ", "\x00 lookup "} {
		plain := strings.Repeat("x", 5000) + before + "3333333333333333"
		result := reassemblyTerminal(sc.reassemblyPlan, reassemblyBang(hex.EncodeToString([]byte(plain))), &assembledBudget{})
		if len(result.findings) != 1 || result.incomplete {
			t.Fatalf("exact lane normalization lost context %q: %+v", before, result)
		}
	}
}

func TestReassemblyKeywordNormalizationBudget(t *testing.T) {
	sc := keywordScanner(t, []string{"lookup"}, 10)
	defer sc.Close()
	plain := strings.Repeat("x", 5000) + "\xff lookup 3333333333333333"
	body := reassemblyBang(hex.EncodeToString([]byte(plain)))
	memo := &decodingMemo{keywordBudget: &keywordWorkBudget{used: maxDecodeTotalBytes}}
	result := reassemblyTerminal(sc.reassemblyPlan, body, &assembledBudget{memo: memo})
	if !result.incomplete || len(result.findings) != 0 {
		t.Fatalf("exact normalization ignored exhausted keyword work: %+v", result)
	}
}

func TestReassemblyKeywordNormalizationCache(t *testing.T) {
	source := "\xff lookup 3333333333333333"
	logical := config.DLPKeywordContext(source)
	start := strings.Index(source, "3333333333333333")
	memo := &decodingMemo{}
	context := keywordCandidateContext{memo: memo}
	first, last, ok := context.assembledNormalizedSpan(source, logical, start, len(source))
	if !ok || logical[first:last] != "3333333333333333" || memo.keywordBudget.used == 0 {
		t.Fatal("exact normalization mapping was not charged")
	}
	used := memo.keywordBudget.used
	if _, _, ok := context.assembledNormalizedSpan(source, logical, start, len(source)); !ok || memo.keywordBudget.used != used {
		t.Fatal("repeated candidate rebuilt the normalized mapping")
	}
}

func TestReassemblyKeywordNormalizedSource(t *testing.T) {
	sc := keywordScanner(t, []string{"lookup"}, 50)
	defer sc.Close()
	encoded := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5040) + "3333333333333333")))
	for _, label := range []string{"lookup", "ＬＯＯＫＵＰ", "looKup"} {
		t.Run(label, func(t *testing.T) {
			body := encoded + " " + label
			terminal := reassemblyTerminal(sc.reassemblyPlan, body, &assembledBudget{})
			if len(terminal.findings) != 1 || terminal.incomplete {
				t.Errorf("normalized source keyword lost in terminal: %+v", terminal)
			}
			if result := sc.ScanTextForDLP(t.Context(), body); !keywordFound(result) || HasInspectionLimit(result.Matches) {
				t.Errorf("normalized source keyword lost in production: %+v", result)
			}
		})
	}
}

func TestReassemblyKeywordUnknownSource(t *testing.T) {
	sc := keywordScanner(t, []string{"lookup"}, 50)
	defer sc.Close()
	body := reassemblyBang(hex.EncodeToString([]byte("3333333333333333")))
	for _, inbound := range []bool{false, true} {
		memo := &decodingMemo{keywordMode: true, keywordUnit: "unrelated", keywordInput: "unavailable", reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true, reassemblyInbound: inbound}
		memo.reassemblyObserve(body)
		result := finishAssembled(TextDLPResult{Clean: true}, memo)
		if !memo.inspectionIncomplete() {
			t.Fatal("unknown source control did not reach incomplete context")
		}
		if !inbound && !HasInspectionLimit(result.Matches) {
			t.Fatal("unknown outbound context did not refuse")
		}
		if inbound && (len(result.Matches) == 0 || result.Matches[0].PatternName != PartialEncodedContentPattern || HasInspectionLimit(result.Matches)) {
			t.Fatalf("unknown inbound context lost partial warning: %+v", result)
		}
	}
}

func TestReassemblyKeywordSourceNormalizationCache(t *testing.T) {
	gate, err := (config.DLPPattern{Name: "Labeled record", Regex: `[0-9]{16}`, Keywords: []string{"lookup"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	for _, exhausted := range []bool{false, true} {
		source := strings.Repeat("\ufdfa", 128) + " lookup 3333333333333333"
		memo := &decodingMemo{keywordBudget: &keywordWorkBudget{}}
		if exhausted {
			memo.keywordBudget.used = maxDecodeTotalBytes - 2*len(source)
			if len(config.DLPKeywordContext(source)) <= len(source) {
				t.Fatal("normalization fixture did not expand")
			}
		}
		context := keywordCandidateContext{memo: memo, exactSources: make(map[string]*string)}
		start := strings.Index(source, "3333333333333333")
		if got := context.assembledSourceKeyword(gate, source, start, len(source)); got == exhausted {
			t.Fatalf("source context result=%v exhausted=%v", got, exhausted)
		}
		used := memo.keywordBudget.used
		if got := context.assembledSourceKeyword(gate, source, start, len(source)); got == exhausted || memo.keywordBudget.used != used {
			t.Fatal("source normalization repeated successful or failed work")
		}
	}
}

func TestReassemblyKeywordSourceNormalizationBudget(t *testing.T) {
	gate, err := (config.DLPPattern{Name: "Labeled record", Regex: `[0-9]{16}`, Keywords: []string{"lookup"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"lookup 3333333333333333", strings.Repeat("\u200b", 100) + "lookup 3333333333333333"} {
		memo := &decodingMemo{keywordBudget: &keywordWorkBudget{}}
		context := keywordCandidateContext{memo: memo, exactSources: make(map[string]*string)}
		logical := config.DLPKeywordContext(source)
		start := strings.Index(source, "3333333333333333")
		if _, _, ok := context.assembledNormalizedSpan(source, logical, start, len(source)); !ok {
			t.Fatal("normalization control did not map")
		}
		available := len(source)
		if source != logical {
			available = len(logical) + keywordSpanBytes
			if available >= len(source) {
				t.Fatal("source fixture did not shrink")
			}
		}
		memo.keywordBudget.used = maxDecodeTotalBytes - available
		if context.assembledSourceKeyword(gate, source, start, len(source)) || !memo.inspectionIncomplete() {
			t.Fatal("source normalization crossed its remaining work budget")
		}
	}
}

func TestReassemblyKeywordLargeUnlabeledValue(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Labeled record", Regex: `[0-9]{16}`, Severity: config.SeverityHigh, Keywords: []string{"lookup"}}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	body := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 200000) + "3333333333333333")))
	result := sc.ScanTextForDLP(t.Context(), body)
	if !result.Clean || len(result.Matches) != 0 {
		t.Fatalf("unlabeled value gained a finding: %+v", result)
	}
}
