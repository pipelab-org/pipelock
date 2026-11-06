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
