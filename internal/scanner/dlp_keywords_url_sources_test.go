// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// URL parsing decodes path and fragment before the encoded-segment walk.
func TestDLPKeywordsPercentEncodedComponents(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	encoded := hex.EncodeToString([]byte(keywordNumber))
	escaped := escapeKeywordURLBytes(encoded)
	for _, component := range []struct {
		name string
		wrap func(string) string
	}{
		{"path", func(v string) string { return "https://www.vendor.example/" + v }},
		{"fragment", func(v string) string { return "https://www.vendor.example/#" + v }},
		{"nested path", func(v string) string { return "https://www.vendor.example/%252F" + v }},
		{"nested fragment", func(v string) string { return "https://www.vendor.example/#%252F" + v }},
		{"query", func(v string) string { return "https://www.vendor.example/?value=" + v }},
		{"userinfo", func(v string) string { return "https://" + v + "@www.vendor.example/" }},
	} {
		for _, tc := range []struct {
			name, prefix string
			want         bool
		}{
			{"absent", "", false},
			{"decoded separator", "%2F", false},
			{"decoded hash", "%23", false},
			{"repeated", escaped + "%2F", false},
			{"plus", "+", false},
			{"nearby", "account-", true},
			{"decoded keyword", "", true},
			{"distant", "account-" + strings.Repeat("x", 70) + "-", false},
		} {
			t.Run(component.name+"/"+tc.name, func(t *testing.T) {
				value := tc.prefix + escaped
				if tc.name == "decoded keyword" {
					value = escapeKeywordURLBytes(hex.EncodeToString([]byte("account " + keywordNumber)))
				}
				parsed, err := url.Parse(component.wrap(value))
				if err != nil {
					t.Fatal(err)
				}
				result, _ := sc.checkDLP(parsed)
				if result.Allowed == tc.want || !result.Allowed && !strings.Contains(result.Reason, keywordPattern) {
					t.Fatalf("want keyword match=%v, got %+v", tc.want, result)
				}
			})
		}
	}
}

func escapeKeywordURLBytes(value string) string {
	var escaped strings.Builder
	for _, b := range []byte(value) {
		_, _ = fmt.Fprintf(&escaped, "%%%02X", b)
	}
	return escaped.String()
}

func TestDLPKeywordsURLSourceViews(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name string
		wrap func(string) string
	}{
		{"query concat", func(v string) string { return "https://www.vendor.example/?a=" + v[:len(v)/2] + "&b=" + v[len(v)/2:] }},
		{"noise stripped path", func(v string) string {
			return "https://www.vendor.example/" + escapeKeywordURLBytes(keywordNumber[:8]+"."+keywordNumber[8:]) + "/" + v
		}},
	} {
		for _, payload := range []struct {
			name, value string
			want        bool
		}{
			{"absent", keywordNumber, false},
			{"decoded keyword", "account " + keywordNumber, true},
			{"distant decoded keyword", "account " + strings.Repeat("x", 70) + " " + keywordNumber, false},
		} {
			t.Run(tc.name+"/"+payload.name, func(t *testing.T) {
				input := tc.wrap(escapeKeywordURLBytes(hex.EncodeToString([]byte(payload.value))))
				parsed, err := url.Parse(input)
				if err != nil {
					t.Fatal(err)
				}
				result, _ := sc.checkDLP(parsed)
				if result.Allowed == payload.want || !result.Allowed && !strings.Contains(result.Reason, keywordPattern) {
					t.Fatalf("want keyword match=%v, got %+v", payload.want, result)
				}
			})
		}
	}
}

func TestDLPKeywordsPercentComponentBudget(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	escaped := escapeKeywordURLBytes(hex.EncodeToString([]byte(keywordNumber)))
	for _, component := range []string{"/", "/#"} {
		parsed, err := url.Parse("https://www.vendor.example" + component + escaped)
		if err != nil {
			t.Fatal(err)
		}
		memo := &decodingMemo{keywordBudget: &keywordWorkBudget{used: maxDecodeTotalBytes}}
		result, _ := sc.checkDLPWithDecodes(parsed, memo)
		if result.Allowed || !memo.inspectionIncomplete() || !strings.Contains(result.Reason, "inspection limit") {
			t.Fatalf("budget exhaustion must refuse: %+v", result)
		}
	}
}

func TestDLPKeywordsURLNoiseStrippedSource(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name, prefix string
		want         bool
	}{
		{"absent", "", false},
		{"nearby", "account/", true},
		{"distant", "account/" + strings.Repeat("x", 70) + "/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := "https://www.vendor.example/" + escapeKeywordURLBytes(tc.prefix+keywordNumber[:8]+"."+keywordNumber[8:])
			parsed, err := url.Parse(input)
			if err != nil {
				t.Fatal(err)
			}
			result, _ := sc.checkDLP(parsed)
			if result.Allowed == tc.want || !result.Allowed && !strings.Contains(result.Reason, keywordPattern) {
				t.Fatalf("want keyword match=%v, got %+v", tc.want, result)
			}
		})
	}
}

func TestDLPKeywordsURLSegmentRegistration(t *testing.T) {
	var absent *decodingMemo
	absent.registerKeywordURLSegments("%33", []string{"3"})
	disabled := &decodingMemo{}
	disabled.registerKeywordURLSegments("%33", []string{"3"})
	if disabled.keywordSources != nil || disabled.keywordBudget != nil {
		t.Fatal("disabled keywords allocated source state")
	}
	for _, tc := range []struct {
		name, source string
		segments     []string
	}{
		{"identity", "plain", []string{"plain"}},
		{"empty and missing", "%33", []string{"", "other", "longer than source"}},
		{"duplicates", "%33%33", []string{"3", "3"}},
		{"plus preserved", "%33+%33", []string{"3+3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memo := &decodingMemo{keywordMode: true}
			memo.registerKeywordURLSegments(tc.source, tc.segments)
			if memo.inspectionIncomplete() {
				t.Fatal("registration incomplete")
			}
			if tc.name == "duplicates" && len(memo.keywordSources["3"]) != 1 {
				t.Fatal("duplicate source edge retained")
			}
			if tc.name == "plus preserved" {
				nodes := memo.keywordSources["3+3"]
				if len(nodes) != 1 || len(nodes[0].logicalContexts()) != 1 || nodes[0].logicalContexts()[0] != "3+3" {
					t.Fatal("plus lost from logical context")
				}
			}
		})
	}
	for _, used := range []int{maxDecodeTotalBytes, maxDecodeTotalBytes - 3*keywordSpanBytes - 2*(keywordSpanBytes*2)} {
		memo := &decodingMemo{keywordMode: true, keywordBudget: &keywordWorkBudget{used: used}}
		memo.registerKeywordURLSegments("%33", []string{"3"})
		if !memo.inspectionIncomplete() {
			t.Fatal("registration must preserve budget exhaustion")
		}
	}
}

func TestDLPKeywordsURLContextFallback(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	escaped := escapeKeywordURLBytes(hex.EncodeToString([]byte(keywordNumber)))
	for _, shape := range []struct {
		name string
		wrap func(string) string
	}{
		{"nested destination", func(v string) string {
			return "https://www.vendor.example/?next=" + url.QueryEscape("https://other.vendor.example/"+v)
		}},
		{"path query seam", func(v string) string {
			return "https://www.vendor.example/" + v[:len(v)/2] + "?v=" + v[len(v)/2:]
		}},
		{"double percent query", func(v string) string {
			return "https://www.vendor.example/?value=%252F" + v
		}},
		{"double percent userinfo", func(v string) string {
			return "https://%252F" + v + "@www.vendor.example/"
		}},
	} {
		for _, tc := range []struct {
			name, label string
			want        bool
		}{
			{"absent", "", false},
			{"URL keyword", "account", true},
			{"decoded keyword elsewhere", hex.EncodeToString([]byte("account")), true},
		} {
			t.Run(shape.name+"/"+tc.name, func(t *testing.T) {
				input := shape.wrap(escaped)
				if tc.label != "" {
					input += "#" + strings.Repeat("x", 70) + "/" + tc.label
				}
				parsed, err := url.Parse(input)
				if err != nil {
					t.Fatal(err)
				}
				for _, check := range []struct {
					name string
					run  func() Result
				}{
					{"configured", func() Result { result, _ := sc.checkDLP(parsed); return result }},
					{"scan", func() Result { return sc.Scan(t.Context(), input) }},
				} {
					t.Run(check.name, func(t *testing.T) {
						result := check.run()
						if result.Allowed == tc.want || !result.Allowed && !strings.Contains(result.Reason, keywordPattern) {
							t.Fatalf("want keyword match=%v, got %+v", tc.want, result)
						}
					})
				}
			})
		}
	}
}

// A distant label qualifies only when the URL candidate has no exact source
// mapping. Mappable URL candidates and text keep their original windows.
func TestDLPKeywordsURLFallbackWindow(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	label := "account/" + strings.Repeat("x", 70) + "/"
	escaped := escapeKeywordURLBytes(hex.EncodeToString([]byte(keywordNumber)))
	for _, tc := range []struct {
		name, input string
		want        bool
	}{
		{"exact path", "https://www.vendor.example/" + label + escaped, false},
		{"fallback query", "https://www.vendor.example/" + label + "?v=%252F" + escaped, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := url.Parse(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			result, _ := sc.checkDLP(parsed)
			if result.Allowed == tc.want || !result.Allowed && !strings.Contains(result.Reason, keywordPattern) {
				t.Fatalf("want keyword match=%v, got %+v", tc.want, result)
			}
		})
	}
	if result := sc.ScanTextForDLP(t.Context(), label+keywordNumber); keywordFound(result) || result.Incomplete {
		t.Fatalf("text must retain exact window: %+v", result)
	}
}

func TestDLPKeywordsURLFallbackContext(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	gate := sc.dlpPatterns[0].keywords
	for _, tc := range []struct {
		name  string
		text  string
		used  int
		want  bool
		limit bool
	}{
		{"absent", "ordinary", 0, false, false},
		{"literal", "ACCOUNT", 0, true, false},
		{"normalized", "аccount", 0, true, false},
		{"whitespace normalized", "acc\tount", 0, true, false},
		{"budget spent", "account", maxDecodeTotalBytes, false, true},
		{"search exhausts budget", "ordinary", maxDecodeTotalBytes - 1, false, true},
		{"normalization exhausts budget", "acc\tount", maxDecodeTotalBytes - len("acc\tount"), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memo := &decodingMemo{
				keywordBudget: &keywordWorkBudget{used: tc.used},
				keywordURL:    &urlKeywordContext{targets: []dlpTarget{{text: tc.text}}},
			}
			ctx := keywordCandidateContext{memo: memo}
			for range 2 { // Cached keyword decisions must preserve the verdict.
				if got := ctx.unavailableURLContext(gate); got != tc.want || memo.inspectionIncomplete() != tc.limit {
					t.Fatalf("match=%v incomplete=%v, want %v/%v", got, memo.inspectionIncomplete(), tc.want, tc.limit)
				}
			}
			if tc.want {
				memo.keywordBudget.incomplete = true
				if ctx.unavailableURLContext(gate) || !memo.inspectionIncomplete() {
					t.Fatal("cached positive must not hide exhausted budget")
				}
			}
		})
	}
	ctx := keywordCandidateContext{}
	if ctx.unavailableURLContext(gate) {
		t.Fatal("missing memo must not qualify")
	}
	ctx.memo = &decodingMemo{}
	if ctx.unavailableURLContext(gate) || !ctx.memo.inspectionIncomplete() {
		t.Fatal("non-URL unavailable context must still refuse")
	}
}

func TestDLPKeywordsURLFallbackMappingBudget(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	gate := sc.dlpPatterns[0].keywords
	// Exceed the existing source-map size bound without allocating a map.
	oversized := strings.Repeat("x", maxDecodeTotalBytes/(2*keywordSpanBytes)+1)
	for _, decoded := range []bool{false, true} {
		t.Run(fmt.Sprint(decoded), func(t *testing.T) {
			memo := &decodingMemo{keywordURL: &urlKeywordContext{targets: []dlpTarget{{text: "account"}}}}
			ctx := keywordCandidateContext{logical: oversized, memo: memo}
			if decoded {
				graph := newKeywordDecodeSources(oversized)
				ctx.decoded = graph.add(oversized, keywordNumber, encodingHex)
				memo.keywordBudget = graph.budget
				ctx.logical = keywordNumber
			}
			if ctx.matches(gate, keywordNumber, 0, len(keywordNumber)) || !memo.inspectionIncomplete() || !memo.keywordBudget.incomplete {
				t.Fatal("mapping size bound must refuse despite a URL-wide keyword")
			}
		})
	}
}

func TestDLPKeywordsURLFallbackSubsequence(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	escaped := escapeKeywordURLBytes(hex.EncodeToString([]byte(keywordNumber)))
	for _, label := range []string{"", "account", hex.EncodeToString([]byte("account"))} {
		t.Run(label, func(t *testing.T) {
			input := "https://www.vendor.example/?a=" + escaped[:len(escaped)/2] + "&skip=ordinary&b=" + escaped[len(escaped)/2:]
			if label != "" {
				input += "#" + strings.Repeat("x", 70) + "/" + label
			}
			parsed, err := url.Parse(input)
			if err != nil {
				t.Fatal(err)
			}
			memo := &decodingMemo{}
			result, _ := sc.checkDLPWithDecodes(parsed, memo)
			want := label != ""
			if result.Allowed == want || !result.Allowed && !strings.Contains(result.Reason, keywordPattern) {
				t.Fatalf("want keyword match=%v, got %+v", want, result)
			}
			if memo.keywordURL != nil || memo.keywordUnit != "" {
				t.Fatal("URL fallback context escaped its scan")
			}
		})
	}
}

// Query combinations append URL targets. A fallback after an append checks only
// the new targets, so repeated combinations can't exhaust the keyword budget.
func TestDLPKeywordsURLFallbackIncremental(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	gate := sc.dlpPatterns[0].keywords
	first := strings.Repeat("a", 64)
	memo := &decodingMemo{keywordURL: &urlKeywordContext{targets: []dlpTarget{{text: first}}}}
	ctx := keywordCandidateContext{memo: memo}
	if ctx.unavailableURLContext(gate) {
		t.Fatal("keyword found in a target without it")
	}
	used := memo.keywordBudget.used
	if used != len(first) {
		t.Fatalf("first fallback charged %d bytes, want %d", used, len(first))
	}
	second := strings.Repeat("b", 32)
	memo.keywordURL.targets = append(memo.keywordURL.targets, dlpTarget{text: second})
	if ctx.unavailableURLContext(gate) || memo.keywordBudget.used != used+len(second) {
		t.Fatalf("second fallback charged %d bytes, want only the new target", memo.keywordBudget.used-used)
	}
	memo.keywordURL.targets = append(memo.keywordURL.targets, dlpTarget{text: "account"})
	if !ctx.unavailableURLContext(gate) {
		t.Fatal("keyword in an appended target was missed")
	}
	used = memo.keywordBudget.used
	memo.keywordURL.targets = append(memo.keywordURL.targets, dlpTarget{text: strings.Repeat("c", 32)})
	if !ctx.unavailableURLContext(gate) || memo.keywordBudget.used != used {
		t.Fatal("a found keyword must stay found without rescanning")
	}
}
