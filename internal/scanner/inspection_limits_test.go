// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The decoder bounds below cap scan cost. Each test puts a credential just
// past one bound, where the scan used to return the views it had produced as
// a complete (clean) result, and asserts a refusal instead, next to a control
// just inside the bound that is still caught as content.

func inspectionLimitScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// inspectionLimitAWSKey is a fake core-floor credential built at runtime.
func inspectionLimitAWSKey() string { return "AK" + "IA" + "Q9W8E7R6T5Y4U3I2" }

// percentEncodeN percent-encodes s, then re-encodes the '%' n-1 more times,
// so n decoding rounds recover s.
func percentEncodeN(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	out := b.String()
	for i := 1; i < n; i++ {
		out = strings.ReplaceAll(out, "%", "%25")
	}
	return out
}

func TestURLPercentRoundsPastCeilingRefused(t *testing.T) {
	t.Parallel()
	s := inspectionLimitScanner(t)
	key := inspectionLimitAWSKey()
	for _, n := range []int{maxDecodeRounds, maxDecodeRounds + 1, maxDecodeRounds + 20} {
		token := percentEncodeN(key[:1], n) + key[1:]
		for _, raw := range []string{
			"https://api.vendor.example/p?k=" + token,
			"https://api.vendor.example/" + token,
		} {
			res := s.Scan(context.Background(), raw)
			if res.Allowed {
				t.Fatalf("n=%d %s: allowed, want refusal", n, raw[:40])
			}
			// A separately decoded URL view can now reveal a concrete credential
			// before the raw component's incomplete status is reported.
			if n > maxDecodeRounds && !IsURLInspectionLimitResult(res) && !strings.Contains(res.Reason, patternNameAWSAccessID) {
				t.Fatalf("n=%d: reason %q, want a limit or recovered credential", n, res.Reason)
			}
			if n <= maxDecodeRounds && IsURLInspectionLimitResult(res) {
				t.Fatalf("n=%d: inside the ceiling must be a content finding, got %q", n, res.Reason)
			}
		}
	}

	// Ordinary single and double encoding stays allowed.
	for _, raw := range []string{
		"https://api.vendor.example/search?q=a%20b&r=%2541",
		"https://api.vendor.example/a%2Fb/c?x=1",
	} {
		if res := s.Scan(context.Background(), raw); !res.Allowed {
			t.Fatalf("%s: refused: %s", raw, res.Reason)
		}
	}
}

func TestURLPercentDecodeConvergesComponents(t *testing.T) {
	t.Parallel()
	deep := percentEncodeN("A", maxDecodeRounds+1)
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"plain", "https://h.example/a?b=c#d", true},
		{"at ceiling", "https://h.example/?k=" + percentEncodeN("A", maxDecodeRounds), true},
		{"query", "https://h.example/?k=" + deep, false},
		{"path", "https://h.example/" + deep, false},
		{"fragment", "https://h.example/#" + deep, false},
		{"userinfo", "https://" + deep + "@h.example/", false},
	} {
		parsed := mustParseURL(t, tc.raw)
		if got := urlPercentDecodeConverges(parsed); got != tc.want {
			t.Errorf("%s: converges=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func htmlNestedFirstChar(secret string, layers int) string {
	return "&" + strings.Repeat("amp;", layers) + fmt.Sprintf("#%d;", secret[0]) + secret[1:]
}

func TestHTMLEntityChainPastPassLimitRefused(t *testing.T) {
	t.Parallel()
	s := inspectionLimitScanner(t)
	key := inspectionLimitAWSKey()
	for _, layers := range []int{maxHTMLEntityDecodePasses - 1, maxHTMLEntityDecodePasses, maxHTMLEntityDecodePasses + 1, 40} {
		text := "note: " + htmlNestedFirstChar(key, layers)
		res := s.ScanTextForDLP(context.Background(), text)
		if res.Clean {
			t.Fatalf("layers=%d: clean, want a finding or refusal", layers)
		}
		past := layers >= maxHTMLEntityDecodePasses
		if past && !HasInspectionLimit(res.Matches) {
			t.Fatalf("layers=%d: matches %v, want the inspection limit", layers, matchNames(res.Matches))
		}
		if !past && HasInspectionLimit(res.Matches) {
			t.Fatalf("layers=%d: inside the limit must be a content finding, got %v", layers, matchNames(res.Matches))
		}
	}

	// Inbound content keeps its delivery contract: no decode-bound refusal.
	inbound := s.ScanTextForDLPInbound(context.Background(), "note: "+htmlNestedFirstChar("hello world", 40))
	if HasInspectionLimit(inbound.Matches) {
		t.Fatal("inbound scan refused at a decode bound")
	}
	// Ordinary escaped text stays clean.
	if res := s.ScanTextForDLP(context.Background(), "Tom &amp;amp; Jerry &lt;b&gt;"); !res.Clean {
		t.Fatalf("ordinary entities: %v", matchNames(res.Matches))
	}
}

func TestHTMLEntityLayerInsideOtherEncodingsDetected(t *testing.T) {
	t.Parallel()
	s := inspectionLimitScanner(t)
	key := inspectionLimitAWSKey()
	// Entity-escape every byte so no plain credential remains anywhere.
	var b strings.Builder
	for i := 0; i < len(key); i++ {
		fmt.Fprintf(&b, "&#%d;", key[i])
	}
	entities := b.String()
	for name, token := range map[string]string{
		"base64(html)":         base64.StdEncoding.EncodeToString([]byte(entities)),
		"base64url(html)":      base64.RawURLEncoding.EncodeToString([]byte(entities)),
		"hex(html)":            hex.EncodeToString([]byte(entities)),
		"base64(base64(html))": base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(entities)))),
	} {
		if res := s.ScanTextForDLP(context.Background(), "data "+token); res.Clean || HasInspectionLimit(res.Matches) {
			t.Errorf("%s text: clean=%v matches=%v, want a content finding", name, res.Clean, matchNames(res.Matches))
		}
		if res := s.Scan(context.Background(), "https://api.vendor.example/u/"+token); res.Allowed {
			t.Errorf("%s URL path: allowed", name)
		}
	}
}

func TestDecodeFixpointCompleteWithinBounds(t *testing.T) {
	t.Parallel()
	key := inspectionLimitAWSKey()
	small := hex.EncodeToString([]byte(hex.EncodeToString([]byte("filler " + key))))
	views, complete := decodeEncodingsFixpointMode(small, true, 0)
	if !complete {
		t.Fatal("small nest reported incomplete")
	}
	found := false
	for _, v := range views {
		found = found || strings.Contains(v.text, key)
	}
	if !found {
		t.Fatal("small nest did not decode to the credential")
	}
	// A depth bound inside a nested layer still reports incomplete.
	deep := base64.StdEncoding.EncodeToString([]byte(htmlNestedFirstChar(key, maxHTMLEntityDecodePasses+2)))
	if _, complete := decodeEncodingsFixpointMode(deep, true, 0); complete {
		t.Fatal("entity chain past the pass limit under base64 reported complete")
	}
}

func TestDecodingMemoCarriesIncompleteAcrossCacheHits(t *testing.T) {
	t.Parallel()
	text := htmlNestedFirstChar("value", maxHTMLEntityDecodePasses+2)
	var first decodingMemo
	first.decode(text, false)
	if !first.inspectionIncomplete() {
		t.Fatal("first decode did not record the incomplete entity chain")
	}
	// A fresh scan state that hits a cached incomplete entry must also be
	// marked, so share the cache and clear only the scan flag.
	first.incomplete = false
	first.decode(text, false)
	if !first.inspectionIncomplete() {
		t.Fatal("cache hit dropped the incomplete flag")
	}
	var nilMemo *decodingMemo
	nilMemo.markIncomplete()
	if nilMemo.inspectionIncomplete() {
		t.Fatal("nil memo reported incomplete")
	}
}

func TestQuerySubsequenceSearchSize(t *testing.T) {
	t.Parallel()
	if got := querySubsequenceMaxCombinations; got != 190+1140+4845 {
		t.Fatalf("20-value combination budget = %d", got)
	}
	for _, tc := range []struct {
		n, size int
		ok      bool
	}{
		{3, SubsequenceMaxSize, true},
		{SubsequenceMaxParts, SubsequenceMaxSize, true},
		{SubsequenceMaxParts + 1, 3, true},
		{33, 3, true},
		{34, 2, true},
		{111, 2, true},
		{112, 0, false},
		{100_000, 0, false},
	} {
		size, ok := querySubsequenceSearchSize(tc.n)
		if size != tc.size || ok != tc.ok {
			t.Errorf("n=%d: size=%d ok=%v, want %d %v", tc.n, size, ok, tc.size, tc.ok)
		}
	}
}

func TestQuerySplitCredentialPastTwentyValuesDetected(t *testing.T) {
	t.Parallel()
	s := inspectionLimitScanner(t)
	creds := map[string]string{
		"Google API Key":   "AI" + "za" + "SyB3x7Kq9mPzR2vW8nT4cL6dF1hJ5gYuE0a",
		"Databricks Token": "dap" + "i" + "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
		"IBAN":             "GB82" + "WEST" + "1234" + "5698" + "7654" + "32",
	}
	for name, cred := range creds {
		if res := s.Scan(context.Background(), "https://c.example/p?k="+cred); res.Allowed {
			t.Fatalf("%s: whole credential allowed; fixture does not match its pattern", name)
		}
		half := len(cred) / 2
		for _, gap := range []int{0, 18, 19, 25, 60} {
			q := []string{"p0=" + cred[:half]}
			for i := 0; i < gap; i++ {
				q = append(q, fmt.Sprintf("m%d=zz", i))
			}
			q = append(q, "p1="+cred[half:])
			raw := "https://c.example/p?" + strings.Join(q, "&")
			if res := s.Scan(context.Background(), raw); res.Allowed {
				t.Errorf("%s gap=%d: split credential allowed", name, gap)
			}
		}
	}
}

func TestQueryValuesPastPairSearchRefused(t *testing.T) {
	t.Parallel()
	s := inspectionLimitScanner(t)
	build := func(n int) string {
		q := make([]string, n)
		for i := range q {
			q[i] = fmt.Sprintf("a%d=%d", i, i%10)
		}
		return "https://c.example/p?" + strings.Join(q, "&")
	}
	if res := s.Scan(context.Background(), build(40)); !res.Allowed {
		t.Fatalf("40 benign values refused: %s", res.Reason)
	}
	res := s.Scan(context.Background(), build(112))
	if res.Allowed || res.Reason != querySubsequenceLimitReason || !IsCoreCriticalResult(res) {
		t.Fatalf("112 values: allowed=%v reason=%q, want the core query-value limit", res.Allowed, res.Reason)
	}
}

func matchNames(matches []TextDLPMatch) []string {
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.PatternName)
	}
	return names
}

func TestDecodeInspectionLimitGuidance(t *testing.T) {
	t.Parallel()
	want := decodeInspectionLimitGuidance()
	if got, ok := GuidanceForResultWithPatterns("body_dlp", "DLP match", []string{UninspectableEncodedContentPattern}); !ok || got != want {
		t.Fatalf("pattern guidance = %+v, %v", got, ok)
	}
	for _, reason := range []string{urlInspectionLimitReason, querySubsequenceLimitReason} {
		if got, ok := GuidanceForResult(ScannerCoreDLP, reason); !ok || got != want {
			t.Fatalf("%q guidance = %+v, %v", reason, got, ok)
		}
	}
	if got, _ := GuidanceForResultWithPatterns("body_dlp", "DLP match", []string{UninspectableJSONNumberPattern}); got == want {
		t.Fatal("JSON number limit took the decode guidance")
	}
}

// Reassembled values and decoded carriers can expose percent escapes that
// are absent from the original URL components.
func TestURLDerivedPercentDecodeLimits(t *testing.T) {
	for _, coreOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("coreOnly=%v", coreOnly), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.APIAllowlist = nil
			if coreOnly {
				cfg.DLP.Patterns = nil
			}
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			key := inspectionLimitAWSKey()
			for _, rounds := range []int{1, maxDecodeRounds, maxDecodeRounds + 1} {
				token := percentEncodeN(key[:1], rounds) + key[1:]
				carriers := map[string]string{
					"joined":       "https://api.vendor.example/?a=" + token[:1] + "&b=" + token[1:],
					"subsequence":  "https://api.vendor.example/?a=" + token[:1] + "&noise=unrelated&b=" + token[1:],
					"base64 query": "https://api.vendor.example/?k=" + base64.RawURLEncoding.EncodeToString([]byte(token)),
					"base64 path":  "https://api.vendor.example/" + base64.RawURLEncoding.EncodeToString([]byte(token)),
				}
				for name, raw := range carriers {
					t.Run(fmt.Sprintf("%s/%d", name, rounds), func(t *testing.T) {
						result := s.Scan(t.Context(), raw)
						if result.Allowed {
							t.Fatalf("allowed %s after %d rounds", name, rounds)
						}
						if rounds > maxDecodeRounds && !IsURLInspectionLimitResult(result) {
							t.Fatalf("past limit: %q", result.Reason)
						}
						if rounds <= maxDecodeRounds && IsURLInspectionLimitResult(result) {
							t.Fatalf("within limit: %q", result.Reason)
						}
					})
				}
			}
		})
	}
}

func TestDerivedPercentLimitBenignRefusal(t *testing.T) {
	s := inspectionLimitScanner(t)
	for _, n := range []int{maxDecodeRounds, maxDecodeRounds + 1} {
		token := percentEncodeN("h", n) + "ello"
		for name, raw := range map[string]string{
			"joined": "https://api.vendor.example/?a=" + token[:1] + "&b=" + token[1:],
			"base64": "https://api.vendor.example/?k=" + base64.RawURLEncoding.EncodeToString([]byte(token)),
		} {
			res := s.Scan(t.Context(), raw)
			if n > maxDecodeRounds && !IsURLInspectionLimitResult(res) {
				t.Errorf("%s n=%d: %+v", name, n, res)
			}
			if n <= maxDecodeRounds && !res.Allowed {
				t.Errorf("%s n=%d: %+v", name, n, res)
			}
		}
	}
}

// The decode walk adds the HTML entity layer without displacing a view the
// entity-free walk produces, including on large text whose entity decoding
// copies most of the input.
func TestDecodeFixpointKeepsEntityFreeViews(t *testing.T) {
	t.Parallel()
	key := inspectionLimitAWSKey()
	encoded := percentEncodeN(key, 2)
	inputs := map[string]string{
		"small":         "a&amp;b " + encoded,
		"base64 entity": base64.StdEncoding.EncodeToString([]byte("x&amp;y " + encoded)),
		"hex url":       hex.EncodeToString([]byte(encoded + "&lt;")),
	}
	if !testing.Short() {
		inputs["large entity text"] = strings.Repeat("Tom &amp; Jerry &lt;b&gt; ", 200_000) + encoded
	}
	for name, input := range inputs {
		// The walk begins with the reference walk, view for view, so the
		// entity layer cannot spend the budget those views had.
		views, _ := decodeEncodingsFixpointMode(input, true, 0)
		reference := referenceDecodeEncodingsFixpoint(input, true)
		if len(views) < len(reference) || !reflect.DeepEqual(views[:len(reference)], reference) {
			t.Fatalf("%s: walk does not begin with the reference walk", name)
		}
		got := map[string]struct{}{}
		for _, v := range views {
			got[v.text] = struct{}{}
		}
		for _, want := range referenceDecodeEncodingsFixpoint(input, true) {
			if _, ok := got[want.text]; !ok {
				t.Fatalf("%s: entity-free view (%s, %d bytes) missing", name, want.encoding, len(want.text))
			}
		}
	}
}

// Adding query values never removes a combination the 20-value search covers.
func TestQueryFourPieceSplitSurvivesWideQuery(t *testing.T) {
	t.Parallel()
	s := inspectionLimitScanner(t)
	cred := "dap" + "i" + "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	pieces := []string{cred[:9], cred[9:18], cred[18:27], cred[27:]}
	for _, n := range []int{SubsequenceMaxParts, SubsequenceMaxParts + 1, 34, 100} {
		var q []string
		for i, piece := range pieces {
			q = append(q, fmt.Sprintf("p%d=%s", i, piece), fmt.Sprintf("j%d=zz", i))
		}
		for len(q) < n {
			q = append(q, fmt.Sprintf("f%d=%d", len(q), len(q)%10))
		}
		raw := "https://c.example/p?" + strings.Join(q, "&")
		if res := s.Scan(context.Background(), raw); res.Allowed {
			t.Errorf("n=%d: four-piece split allowed", n)
		}
	}
}
