// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordsHostnameViews(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.IncludeDefaults = ptrBool(false)
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	// Isolate keyword gating from the independent chunked-host entropy rule.
	cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions = []string{"*.vendor.example"}
	cfg.DLP.Patterns = []config.DLPPattern{{Name: keywordPattern, Regex: `[0-9]{16}`, Severity: config.SeverityHigh, Keywords: []string{"account"}}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	number := "4111" + strings.Repeat("1", 12)
	for _, tc := range []struct {
		name, payload, path string
		want                bool
	}{
		{"decoded keyword", "account " + number, "/", true},
		{"no keyword", number, "/", false},
		{"URL keyword", number, "/account", true},
		{"distant URL keyword", number, "/" + strings.Repeat("x", 60) + "/account", false},
	} {
		for encoding, encoded := range hostnameLabelEncodings(tc.payload) {
			t.Run(tc.name+"/"+encoding, func(t *testing.T) {
				input := "https://" + hostnameLabelCarrier(encoded, 12) + ".vendor.example" + tc.path
				assertKeywordURLVerdict(t, sc, input, tc.want)
			})
		}
	}
	t.Run("plain host", func(t *testing.T) {
		assertKeywordURLVerdict(t, sc, "https://www.vendor.example/docs", false)
	})
	// The collapsed full-host view uses the same source coordinates even when
	// the candidate is plain digits split across labels, rather than encoded.
	assertKeywordURLVerdict(t, sc, "https://"+hostnameLabelCarrier(number, 12)+".vendor.example/account", true)
	assertKeywordURLVerdict(t, sc, "https://"+hostnameLabelCarrier(number, 12)+".vendor.example/", false)
	// Without an explicit entropy exclusion, that independent rule still
	// blocks a chunked hex carrier after the keyword gate rejects it.
	cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions = nil
	defaultEntropy := MustNew(cfg)
	t.Cleanup(defaultEntropy.Close)
	input := "https://" + hostnameLabelCarrier(hex.EncodeToString([]byte(number)), 12) + ".vendor.example/"
	if result := defaultEntropy.Scan(t.Context(), input); result.Allowed || result.Scanner != ScannerSubdomainEntropy {
		t.Fatalf("independent entropy rule changed: %+v", result)
	}
}

func assertKeywordURLVerdict(t *testing.T, sc *Scanner, input string, want bool) {
	t.Helper()
	parsed, err := url.Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	configured, _ := sc.checkDLP(parsed)
	for name, result := range map[string]Result{
		"configured": configured,
		"Scan":       sc.Scan(t.Context(), input),
	} {
		if result.Allowed == want || !result.Allowed && (result.Scanner != ScannerDLP || !strings.Contains(result.Reason, keywordPattern)) {
			t.Errorf("%s: want keyword match=%v, got %+v", name, want, result)
		}
	}
}

func TestDLPKeywordsHostnameBudget(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	encoded := hex.EncodeToString([]byte(keywordNumber))
	parsed, err := url.Parse("https://" + hostnameLabelCarrier(encoded, 12) + ".vendor.example/")
	if err != nil {
		t.Fatal(err)
	}
	memo := &decodingMemo{keywordBudget: &keywordWorkBudget{used: maxDecodeTotalBytes}}
	result, _ := sc.checkDLPWithDecodes(parsed, memo)
	if result.Allowed || !memo.inspectionIncomplete() || !strings.Contains(result.Reason, "inspection limit") {
		t.Fatalf("exhausted keyword budget must refuse inspection: %+v", result)
	}
}

func TestDLPKeywordsURLComponentViews(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name string
		url  func(string) string
	}{
		{"path", func(value string) string { return "https://www.vendor.example/" + value }},
		{"query", func(value string) string { return "https://www.vendor.example/?value=" + value }},
		{"userinfo", func(value string) string { return "https://" + value + "@www.vendor.example/" }},
		{"fragment", func(value string) string { return "https://www.vendor.example/#" + value }},
	} {
		for _, keyword := range []bool{false, true} {
			payload := keywordNumber
			if keyword {
				payload = "account " + payload
			}
			for encoding, encoded := range hostnameLabelEncodings(payload) {
				t.Run(tc.name+"/"+encoding+"/"+payload, func(t *testing.T) {
					assertKeywordURLVerdict(t, sc, tc.url(encoded), keyword)
				})
			}
		}
	}
}
