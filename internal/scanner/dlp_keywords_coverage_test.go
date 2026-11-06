// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordsDirectSpanContexts(t *testing.T) {
	gate, err := (config.DLPPattern{Name: keywordPattern, Keywords: []string{"account"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, source string
		want         bool
	}{
		{"labeled", "account " + keywordNumber, true},
		{"unlabeled", keywordNumber, false},
		{"empty", "", false},
		{"distant", "account" + strings.Repeat(" ", config.DefaultDLPKeywordWindow) + keywordNumber, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := compiledPattern{re: regexp.MustCompile(`[0-9]{16}`), keywords: gate}
			for _, joined := range []bool{false, true} {
				start, end, ok := p.matchSpanInView(tc.source, tc.source)
				if joined {
					view, offsets := compactTextDLPWhitespaceWithOffsets(tc.source)
					start, end, ok = p.matchSpanInJoinedView(view, tc.source, offsets)
					if ok && view[start:end] != keywordNumber {
						t.Fatal("joined span does not identify candidate")
					}
				} else if ok && tc.source[start:end] != keywordNumber {
					t.Fatal("span does not identify candidate")
				}
				if ok != tc.want {
					t.Fatalf("joined=%v match=%v, want %v", joined, ok, tc.want)
				}
			}
			if p.keywordContext != nil {
				t.Fatal("scan-local context mutated pattern")
			}
		})
	}
	if !ValidatedPatternMatches(keywordNumber, regexp.MustCompile(`[0-9]{16}`), nil, false, false) {
		t.Fatal("legacy matcher lost candidate")
	}
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	result := sc.ScanTextForDLP(t.Context(), "account "+keywordNumber)
	found := false
	for _, match := range result.Matches {
		if match.PatternName == keywordPattern {
			found = match.RequiresKeywordContext()
		}
	}
	if !found {
		t.Fatal("keyword finding lost redaction context requirement")
	}
}

func TestDLPKeywordsSourceBudgetBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name        string
		used, nodes int
		want        bool
	}{
		{"room", 0, 0, true},
		{"last node", 0, maxDecodeCandidates - 1, true},
		{"node exhaustion", 0, maxDecodeCandidates, false},
		{"exact bytes", maxDecodeTotalBytes - keywordNodeBytes, 0, true},
		{"byte exhaustion", maxDecodeTotalBytes - keywordNodeBytes + 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph := newKeywordDecodeSources("root")
			graph.budget.used, graph.budget.nodes = tc.used, tc.nodes
			if got := graph.chargeNode(); got != tc.want {
				t.Fatalf("charged=%v, want %v", got, tc.want)
			}
			if !tc.want && (!graph.incomplete || !graph.budget.incomplete || graph.budget.used != tc.used || graph.budget.nodes != tc.nodes) {
				t.Fatal("exhaustion lost incomplete state or charged rejected node")
			}
		})
	}
	for _, tc := range []struct {
		name     string
		rootUsed int
		parent   string
	}{
		{"root exhausted", maxDecodeTotalBytes, "root"},
		{"missing parent", 0, "absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph := newKeywordDecodeSources("root")
			graph.budget.used = tc.rootUsed
			if node := graph.add(tc.parent, "child", "identity"); node != nil || !graph.incomplete {
				t.Fatal("unavailable parent admitted a child")
			}
		})
	}
}

func TestDLPKeywordsMappingBudgetBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, source, view string
		used               int
	}{
		{"decoded mapping size", "root", strings.Repeat("x", maxDecodeTotalBytes/keywordSpanBytes+1), 0},
		{"source mapping size", strings.Repeat("x", maxDecodeTotalBytes/(2*keywordSpanBytes)+1), "view", 0},
		{"remaining mapping budget", "root", "view", maxDecodeTotalBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph := newKeywordDecodeSources(tc.source)
			node := graph.add(tc.source, tc.view, encodingHex)
			if node == nil {
				t.Fatal("node allocation failed before mapping")
			}
			graph.budget.used = tc.used
			visited := false
			if node.visitOneSource(0, 1, func(string, int, int) bool { visited = true; return true }) || visited || !graph.incomplete || !node.mapped {
				t.Fatal("unavailable map accepted source")
			}
			memo := &decodingMemo{keywordBudget: &keywordWorkBudget{used: tc.used}}
			context := keywordCandidateContext{memo: memo}
			if _, _, ok := context.projectionSpan(tc.source, tc.view, 0, 1); ok || !memo.incomplete {
				t.Fatal("unavailable projection silently accepted")
			}
		})
	}
	for _, tc := range []struct {
		name       string
		start, end int
	}{
		{"negative", -1, 1}, {"empty", 0, 0}, {"reversed", 2, 1}, {"past end", 0, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph := newKeywordDecodeSources("root")
			called := false
			visit := func(string, int, int) bool { called = true; return true }
			var absent *keywordDecodeSource
			if absent.visitSources(tc.start, tc.end, visit) || graph.nodes["root"].visitSources(tc.start, tc.end, visit) || called {
				t.Fatal("invalid span visited source")
			}
			context := keywordCandidateContext{}
			if _, _, ok := context.projectionSpan("root", "roo", tc.start, tc.end); ok {
				t.Fatal("invalid projection coordinates accepted")
			}
		})
	}
}

func TestDLPKeywordsUnavailableCandidateContexts(t *testing.T) {
	gate, err := (config.DLPPattern{Name: keywordPattern, Keywords: []string{"account"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		context        keywordCandidateContext
		view           string
		wantIncomplete bool
	}{
		{"empty context", keywordCandidateContext{}, keywordNumber, false},
		{"empty view", keywordCandidateContext{}, "", false},
		{"missing source", keywordCandidateContext{sourceUnavailable: true}, keywordNumber, true},
		{"bad projection", keywordCandidateContext{logical: "different"}, keywordNumber, true},
		{"bad offsets", keywordCandidateContext{logical: "account " + keywordNumber, offsets: []int{8}}, keywordNumber, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memo := &decodingMemo{}
			tc.context.memo = memo
			if tc.context.matches(gate, tc.view, 0, len(tc.view)) || memo.incomplete != tc.wantIncomplete {
				t.Fatalf("incomplete=%v, want %v", memo.incomplete, tc.wantIncomplete)
			}
		})
	}
	source := base64.StdEncoding.EncodeToString([]byte(keywordNumber))
	graph := newKeywordDecodeSources(source)
	node := graph.add(source, keywordNumber, encodingBase64)
	// Mapping may be unavailable even when a decoded view was retained.
	context := keywordCandidateContext{decoded: node, logical: "unrelated", memo: &decodingMemo{}}
	if context.matches(gate, "not-a-view", 0, 10) || !context.memo.incomplete {
		t.Fatal("unmapped candidate silently clean")
	}
	graph.budget.used = maxDecodeTotalBytes
	context = keywordCandidateContext{alternatives: []*keywordDecodeSource{node}, source: source, memo: &decodingMemo{keywordBudget: graph.budget}}
	if context.matches(gate, keywordNumber, 0, len(keywordNumber)) || !context.memo.incomplete {
		t.Fatal("unavailable source context silently clean")
	}
}

func TestDLPKeywordsOffsetRecoveryFailures(t *testing.T) {
	for _, tc := range []struct{ name, source, view, encoding string }{
		{"identity mismatch", "abc", "abd", "identity"},
		{"unknown transform", "abc", "abc", "unsupported"},
		{"invalid base64", "!", "abc", encodingBase64},
		{"invalid base32", "!", "abc", encodingBase32},
		{"invalid hex", "not hex", "abc", encodingHex},
		{"nonconverging URL", "%" + strings.Repeat("25", maxDecodeRounds+1) + "41", "A", encodingURL},
		{"unchanged HTML", "plain", "different", encodingHTML},
		{"query mismatch", "a=abc", "different", keywordQueryValues},
		{"percent mismatch", "%zzabc", "different", keywordPercentDrop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := keywordDecodeOffsets(tc.source, tc.view, tc.encoding); got != nil {
				t.Fatalf("mismatched producer supplied offsets: %v", got)
			}
		})
	}
	context := keywordCandidateContext{}
	if start, end, ok := context.projectionSpan("account", "account", 0, 7); !ok || start != 0 || end != 7 {
		t.Fatal("identity projection lost coordinates")
	}
	if got := keywordBitOffsets([]keywordByteSpan{{0, 1}}, 2, 6); got != nil {
		t.Fatalf("truncated symbols mapped: %v", got)
	}
	for _, tc := range []struct {
		source, decoded string
		extra           int
	}{
		{"%41%zzabc", "%41zzabc", 0}, {"%41%zzabc", "%41abc", 2},
	} {
		got := keywordPercentOffsets(tc.source, tc.decoded, tc.extra)
		if len(got) != len(tc.decoded) || got[0] != (keywordByteSpan{0, 1}) {
			t.Fatalf("percent offsets=%v", got)
		}
	}
	for _, tc := range []struct {
		source, view                   string
		start, end, wantStart, wantEnd int
	}{
		{"ａｂｃ", "abc", 0, 3, 0, 9},
		{`\uD83D\uDE00`, "😀", 0, 4, 0, 12},
	} {
		if strings.HasPrefix(tc.source, `\u`) {
			got := keywordDecodeOffsets(tc.source, tc.view, encodingJSONUnicode)
			if len(got) != len(tc.view) || got[0].start != tc.wantStart || got[len(got)-1].end != tc.wantEnd {
				t.Fatalf("surrogate map=%v", got)
			}
		} else if start, end, ok := keywordNormalizedSpan(tc.source, tc.view, tc.start, tc.end); !ok || start != tc.wantStart || end != tc.wantEnd {
			t.Fatalf("normalized span=(%d,%d,%v)", start, end, ok)
		}
	}
}

func TestDLPKeywordsSourceGraphReuse(t *testing.T) {
	graph := newKeywordDecodeSources("root")
	first := graph.add("root", "first", "projection")
	second := graph.add("first", "second", "projection")
	// A repeated edge is reused; a reverse edge must not introduce a cycle.
	if graph.add("root", "first", "projection") != first || graph.add("second", "first", "projection") != first || len(first.variants) != 0 {
		t.Fatal("repeated or cyclic source edge changed graph")
	}
	root := graph.nodes["root"]
	graph.bindParents("root", []*keywordDecodeSource{root, second})
	if root.parent != nil {
		t.Fatal("binding introduced a cycle")
	}
	other := newKeywordDecodeSources("root")
	graph.bindParents("root", []*keywordDecodeSource{other.nodes["root"]})
	if root.parent != other.nodes["root"] || root.encoding != "identity" {
		t.Fatal("equal-text parent lost identity mapping")
	}
	graph.bindParents("root", []*keywordDecodeSource{other.nodes["root"]})
	parent := newKeywordDecodeSources("another source").nodes["another source"]
	graph.bindParents("root", []*keywordDecodeSource{parent, parent})
	if len(root.variants) != 1 {
		t.Fatal("duplicate producing path retained")
	}
	graph.budget.nodes = maxDecodeCandidates
	if graph.add("root", "first", encodingHex) != first || !graph.budget.incomplete {
		t.Fatal("variant exhaustion lost prior node or incomplete flag")
	}
	unseen := newKeywordDecodeSources("unseen").nodes["unseen"]
	graph.bindParents("root", []*keywordDecodeSource{unseen})
	if len(root.variants) != 1 || !graph.incomplete {
		t.Fatal("parent budget exhaustion changed retained edges")
	}
	var absent *keywordDecodeSource
	if absent.hasSourceAncestor(root) {
		t.Fatal("nil source has an ancestor")
	}
}

func TestDLPKeywordsLogicalContextBudget(t *testing.T) {
	for _, tc := range []struct{ name, source, decoded, encoding, want string }{
		{"identity", "account", "account", "identity", "account"},
		{"percent deletion", "%zzaccount", "zzaccount", keywordPercentDrop, "zzaccount"},
		{"percent escape deletion", "%zzaccount", "account", keywordPercentEscapeDrop, "account"},
		{"projection preserves distance", "account 123", "account123", "projection", "account 123"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph := newKeywordDecodeSources(tc.source)
			node := graph.add(tc.source, tc.decoded, tc.encoding)
			if tc.source == tc.decoded {
				node = graph.nodes[tc.source]
			}
			got := node.logicalContexts()
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("logical contexts=%q, want %q", got, tc.want)
			}
			if tc.source != tc.decoded {
				node.logicalReady = false
				graph.budget.used = maxDecodeTotalBytes
				got = node.logicalContexts()
				if tc.want != tc.decoded && (len(got) != 0 || !node.logicalUnavailable) {
					t.Fatalf("unavailable logical context=%q, flag=%v", got, node.logicalUnavailable)
				}
			}
		})
	}
	graph := newKeywordDecodeSources("account " + keywordNumber)
	node := graph.add(graph.root, keywordNumber, "projection")
	graph.budget.used = maxDecodeTotalBytes
	memo := &decodingMemo{keywordBudget: graph.budget}
	gate, err := (config.DLPPattern{Name: keywordPattern, Keywords: []string{"account"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	context := keywordCandidateContext{alternatives: []*keywordDecodeSource{node}, memo: memo}
	if context.matches(gate, keywordNumber, 0, len(keywordNumber)) || !memo.incomplete {
		t.Fatal("unavailable alternative context silently accepted")
	}
	// Retaining two edges with the same effective logical text must not duplicate it.
	graph = newKeywordDecodeSources("%61ccount")
	node = graph.add(graph.root, "account", encodingURL)
	graph.add(graph.root, "account", encodingHTML)
	if got := node.logicalContexts(); len(got) != 2 {
		t.Fatalf("distinct logical contexts=%q", got)
	}
	graph.add(graph.root, "account", keywordQueryValues)
	if got := node.logicalContexts(); len(got) != 2 {
		t.Fatalf("duplicate logical context retained: %q", got)
	}
}

func TestDLPKeywordsRawSourceAndEncodingSymbols(t *testing.T) {
	gate, err := (config.DLPPattern{Name: keywordPattern, Keywords: []string{"account"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, source string
		used         int
		want         bool
	}{
		{"root context", "account " + base64.StdEncoding.EncodeToString([]byte(keywordNumber)), 0, true},
		{"source search budget", "account " + base64.StdEncoding.EncodeToString([]byte(keywordNumber)), maxDecodeTotalBytes, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Decode only the value, retaining its label in the scan's original unit.
			encoded := base64.StdEncoding.EncodeToString([]byte(keywordNumber))
			graph := newKeywordDecodeSources(encoded)
			node := graph.add(encoded, keywordNumber, encodingBase64)
			if tc.used > 0 {
				_ = node.visitOneSource(0, len(keywordNumber), func(string, int, int) bool { return false })
				// Leave exactly enough for the two source visits, but none for searching the original unit.
				graph.budget.used = maxDecodeTotalBytes - 2*keywordSpanBytes
			}
			memo := &decodingMemo{keywordBudget: graph.budget}
			context := keywordCandidateContext{source: tc.source, decoded: node, memo: memo}
			got := context.matches(gate, keywordNumber, 0, len(keywordNumber))
			if got != tc.want || !tc.want && !memo.incomplete {
				t.Fatalf("matched=%v incomplete=%v", got, memo.incomplete)
			}
			if tc.want {
				// Without a separate unit, a decoded root can itself carry the label.
				rootGraph := newKeywordDecodeSources("account " + keywordNumber)
				context = keywordCandidateContext{decoded: rootGraph.nodes[rootGraph.root], logicalUnavailable: true}
				if !context.matches(gate, rootGraph.root, len("account "), len(rootGraph.root)) {
					t.Fatal("root source label lost")
				}
			}
		})
	}
	for _, tc := range []struct{ name, source, decoded, encoding string }{
		{"hex prefixes", `0x330X33\x33\X33`, "3333", encodingHex},
		{"base64 line breaks", "MzMz\r\nMw==", "3333", encodingBase64},
		{"lowercase base32", "gmztgmy=", "3333", encodingBase32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			offsets := keywordDecodeOffsets(tc.source, tc.decoded, tc.encoding)
			if len(offsets) != len(tc.decoded) {
				t.Fatalf("offsets=%v", offsets)
			}
			for _, span := range offsets {
				if span.start < 0 || span.end > len(tc.source) || span.end <= span.start {
					t.Fatalf("invalid span=%+v", span)
				}
			}
		})
	}
}
