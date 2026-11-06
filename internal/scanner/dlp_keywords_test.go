// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	keywordNumber  = "3333333333333333"
	keywordPattern = "Customer identifier"
)

func keywordScanner(t *testing.T, keywords []string, window int) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SeedPhraseDetection.Enabled = new(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: keywordPattern, Regex: `[0-9]{16}`, Severity: config.SeverityHigh, Keywords: keywords}}
	if window != 0 {
		cfg.DLP.Patterns[0].KeywordWindow = new(window)
	}
	sc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func keywordFound(result TextDLPResult) bool {
	for _, match := range result.Matches {
		if match.PatternName == keywordPattern {
			return true
		}
	}
	return false
}

func TestDLPKeywordsPlainContext(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 10)
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"before", "account: " + keywordNumber, true},
		{"after", keywordNumber + " ACCOUNT", true},
		{"absent", keywordNumber, false},
		{"exact before", "account   " + keywordNumber, true},
		{"outside before", "account    " + keywordNumber, false},
		{"exact after", keywordNumber + "   account", true},
		{"outside after", keywordNumber + "    account", false},
		{"runes", "account界界界" + keywordNumber, true},
		{"rune overflow", "account界界界界" + keywordNumber, false},
		{"decoy then labeled", keywordNumber + strings.Repeat(" ", 70) + "account " + keywordNumber, true},
		{"newline distance", "account" + strings.Repeat("\n", 20) + keywordNumber, false},
		{"compacted distance", "account" + strings.Repeat(" ", 5000) + keywordNumber, false},
		{"unicode whitespace distance", "account" + strings.Repeat("\u00a0", 100) + keywordNumber, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, scan := range []func(context.Context, string) TextDLPResult{sc.ScanTextForDLP, sc.ScanRequestBodyTextForDLP, sc.ScanTextForDLPInbound, sc.ScanTextForDLPQuiet} {
				result := scan(t.Context(), tc.text)
				if got := keywordFound(result); got != tc.want {
					t.Fatalf("got=%v want=%v result=%+v", got, tc.want, result)
				}
				if HasInspectionLimit(result.Matches) {
					t.Fatalf("plain context unexpectedly incomplete: %+v", result)
				}
			}
		})
	}
}

func TestDLPKeywordsEncodedContext(t *testing.T) {
	encoders := []struct {
		name   string
		encode func(string) string
	}{
		{encodingHex, func(s string) string { return hex.EncodeToString([]byte(s)) }},
		{encodingDecimal, func(s string) string {
			codes := make([]string, 0, len(s))
			for _, c := range []byte(s) {
				codes = append(codes, fmt.Sprintf("%d", c))
			}
			return strings.Join(codes, " ")
		}},
		{encodingOctal, func(s string) string {
			codes := make([]string, 0, len(s))
			for _, c := range []byte(s) {
				codes = append(codes, fmt.Sprintf("0o%o", c))
			}
			return strings.Join(codes, " ")
		}},
		{encodingQuotedPrintable, func(s string) string {
			var b strings.Builder
			for _, c := range []byte(s) {
				_, _ = fmt.Fprintf(&b, "=%02X", c)
			}
			return b.String()
		}},
		{encodingBase64, func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }},
		{"base64url", func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }},
		{encodingBase32, func(s string) string { return base32.StdEncoding.EncodeToString([]byte(s)) }},
		{"base32hex", func(s string) string { return base32.HexEncoding.EncodeToString([]byte(s)) }},
		{encodingURL, func(s string) string {
			var b strings.Builder
			for _, c := range []byte(s) {
				_, _ = fmt.Fprintf(&b, "%%%02x", c)
			}
			return b.String()
		}},
		{encodingJSONUnicode, func(s string) string {
			var b strings.Builder
			for _, c := range s {
				_, _ = fmt.Fprintf(&b, `\u%04x`, c)
			}
			return b.String()
		}},
		{encodingHTML, func(s string) string {
			var b strings.Builder
			for _, c := range s {
				_, _ = fmt.Fprintf(&b, "&#%d;", c)
			}
			return b.String()
		}},
		{encodingUnicodeTags, func(s string) string {
			var b strings.Builder
			for _, c := range s {
				b.WriteRune(0xe0000 + c)
			}
			return b.String()
		}},
		{"nested hex", func(s string) string { return hex.EncodeToString([]byte(hex.EncodeToString([]byte(s)))) }},
		{"separated hex", func(s string) string { return hexByteSep(hex.EncodeToString([]byte(s)), " ") }},
	}
	sc := keywordScanner(t, []string{"account"}, 50)
	for _, enc := range encoders {
		t.Run(enc.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, text string
				want       bool
			}{
				{"source only", "account: " + enc.encode(keywordNumber), true},
				{"decoded only", enc.encode("account: " + keywordNumber), true},
				{"neither", enc.encode(keywordNumber), false},
				{"outside source window", "account" + strings.Repeat(" ", 100) + enc.encode(keywordNumber), false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					result := sc.ScanTextForDLP(t.Context(), tc.text)
					if got := keywordFound(result); got != tc.want {
						t.Fatalf("got=%v want=%v: %+v", got, tc.want, result)
					}
					if HasInspectionLimit(result.Matches) {
						t.Fatalf("context incomplete: %+v", result)
					}
					if tc.want {
						expected := sha256.Sum256([]byte(keywordNumber))
						found := false
						for _, match := range result.Matches {
							id, ok := match.ValueIdentity()
							if match.PatternName == keywordPattern && ok && id == expected {
								found = true
							}
						}
						if !found {
							t.Fatalf("finding lost original candidate identity: %+v", result)
						}
					}
				})
			}
		})
	}
}

func TestDLPKeywordsCandidateAcceptance(t *testing.T) {
	card := "41111111" + "11111111"
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = []config.DLPPattern{{Name: keywordPattern, Regex: `[0-9]{16}`, Severity: config.SeverityHigh, Validator: config.ValidatorLuhn, Keywords: []string{"payment"}}}
	sc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"payment " + keywordNumber, false},
		{"payment " + card, true},
		{card, false},
		{"payment " + keywordNumber + " " + card, true},
	} {
		if got := keywordFound(sc.ScanTextForDLP(t.Context(), tc.text)); got != tc.want {
			t.Errorf("%q: got=%v", tc.text, got)
		}
	}
	// A keyword inside the candidate cannot authorize that same match.
	p := config.DLPPattern{Name: "overlap", Regex: `account[0-9]+`, Keywords: []string{"account"}}
	gate, err := p.CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	cp := compiledPattern{re: regexp.MustCompile(p.Regex), keywords: gate}
	if cp.matches("account1234") {
		t.Fatal("self-corroboration accepted")
	}
	if !cp.matches("account account1234") {
		t.Fatal("independent label rejected")
	}
	// Vacuity control: disabling the predicate restores the unlabeled candidate.
	cp.keywords = nil
	if !cp.matches("account1234") {
		t.Fatal("positive control did not reach regex candidate")
	}
}

func TestDLPKeywordsURL(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	for _, tc := range []struct {
		input string
		want  bool
	}{
		{"https://api.vendor.example/account/" + keywordNumber, true},
		{"https://api.vendor.example/value/" + keywordNumber, false},
		{"https://api.vendor.example/?account=" + keywordNumber, true},
		{"https://api.vendor.example/?value=" + keywordNumber, false},
		{"https://api.vendor.example/account/" + hex.EncodeToString([]byte(keywordNumber)), true},
		{"https://api.vendor.example/?account=" + base64.StdEncoding.EncodeToString([]byte(keywordNumber)), true},
	} {
		u, err := url.Parse(tc.input)
		if err != nil {
			t.Fatal(err)
		}
		result, _ := sc.checkDLP(u)
		if got := !result.Allowed && strings.Contains(result.Reason, keywordPattern); got != tc.want {
			t.Errorf("%s: got=%v want=%v %+v", tc.input, got, tc.want, result)
		}
	}
}

func TestDLPKeywordsContextCacheIsolation(t *testing.T) {
	gated := keywordScanner(t, []string{"account"}, 50)
	ungated := keywordScanner(t, nil, 0)
	encoded := base64.StdEncoding.EncodeToString([]byte(keywordNumber))
	ctx, release := WithSharedDecodes(t.Context())
	defer release()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for _, sc := range []*Scanner{gated, ungated} {
				for _, prefix := range []string{"", "account: "} {
					got := keywordFound(sc.ScanTextForDLP(ctx, prefix+encoded))
					want := sc == ungated || prefix != ""
					if got != want {
						t.Errorf("context/scanner cache mixed decisions: got=%v want=%v", got, want)
					}
				}
			}
		})
	}
	wg.Wait()
}

func TestDLPKeywordsWarnAndIndependentBlock(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = []config.DLPPattern{
		{Name: keywordPattern, Regex: `[0-9]{16}`, Severity: config.SeverityHigh, Keywords: []string{"account"}, Action: config.ActionWarn},
		{Name: "independent credential", Regex: `credential_[A-Z]{8}`, Severity: config.SeverityHigh},
	}
	sc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	warnings := 0
	sc.SetDLPWarnHook(func(context.Context, string, string) { warnings++ })
	if result := sc.ScanTextForDLP(t.Context(), keywordNumber); !result.Clean || len(result.InformationalMatches) != 0 || warnings != 0 {
		t.Fatalf("missing keyword emitted finding: %+v", result)
	}
	result := sc.ScanTextForDLP(t.Context(), "account "+keywordNumber+" credential_ABCDEFGH")
	if result.Clean || warnings != 1 || len(result.InformationalMatches) == 0 {
		t.Fatalf("warn gate hid blocking rule: %+v warnings=%d", result, warnings)
	}
	coreValue := "gh" + "p_" + strings.Repeat("a", 36)
	if core := sc.ScanTextForDLP(t.Context(), coreValue); !ContainsCoreCriticalMatch(core.Matches) {
		t.Fatal("keyword-free core credential lost independent enforcement")
	}
}

func TestDLPKeywordsSourceCoordinates(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SeedPhraseDetection.Enabled = new(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: keywordPattern, Regex: `identifier_[0-9]{16}`, Keywords: []string{"account"}}}
	sc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	payload := "identifier_" + keywordNumber
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"source before prefix", "account " + hex.EncodeToString([]byte(strings.Repeat("x", 60)+payload)), false},
		{"source after suffix", hex.EncodeToString([]byte(payload+strings.Repeat("x", 60))) + " account", false},
		{"label near exact candidate", hex.EncodeToString([]byte(strings.Repeat("x", 100))) + " account " + hex.EncodeToString([]byte(payload)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := sc.ScanTextForDLP(t.Context(), tc.text)
			if got := keywordFound(result); got != tc.want {
				t.Fatalf("found=%v want=%v: %+v", got, tc.want, result)
			}
		})
	}
	cfg.DLP.Patterns[0].Keywords = []string{"秘密词"}
	hidden, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hidden.Close)
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	inside := encoded[:12] + " 秘密词 " + encoded[12:]
	if result := hidden.ScanTextForDLP(t.Context(), inside); keywordFound(result) {
		t.Fatalf("keyword inside source hull corroborated candidate: %+v", result)
	}
	if result := hidden.ScanTextForDLP(t.Context(), "秘密词 "+encoded); !keywordFound(result) {
		t.Fatal("outside-hull positive control did not qualify")
	}
}

func BenchmarkDLPKeywords(b *testing.B) {
	for _, name := range []string{"omitted", "sparse", "dense", "maximum terms", "unicode", "encoded"} {
		b.Run(name, func(b *testing.B) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.SeedPhraseDetection.Enabled = new(false)
			terms := []string{"account"}
			if name == "omitted" {
				terms = nil
			}
			if name == "maximum terms" {
				terms = nil
				for i := range 50 {
					terms = append(terms, fmt.Sprintf("label%02d%s", i, strings.Repeat("x", 83)))
				}
			}
			cfg.DLP.Patterns = []config.DLPPattern{{Name: keywordPattern, Regex: `[0-9]{16}`, Keywords: terms, KeywordWindow: nil}}
			if name == "maximum terms" {
				cfg.DLP.Patterns[0].KeywordWindow = new(300)
			}
			sc, err := New(cfg)
			if err != nil {
				b.Fatal(err)
			}
			defer sc.Close()
			text := strings.Repeat("ordinary text ", 100) + keywordNumber
			switch name {
			case "dense":
				text = strings.Repeat(keywordNumber+" ", 100)
			case "unicode":
				text = strings.Repeat("界", 100) + "account " + keywordNumber
			case "encoded":
				text = "account " + base64.StdEncoding.EncodeToString([]byte(keywordNumber))
			}
			b.SetBytes(int64(len(text)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				sc.ScanTextForDLP(b.Context(), text)
			}
		})
	}
}

func TestDLPKeywordsMappingLimits(t *testing.T) {
	rule := config.DLPPattern{Name: keywordPattern, Regex: `[0-9]{16}`, Keywords: []string{"account"}}
	gate, err := rule.CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	graph := newKeywordDecodeSources("not an encoding")
	node := graph.add("not an encoding", keywordNumber, encodingHex)
	memo := &decodingMemo{keywordBudget: graph.budget}
	ctx := keywordCandidateContext{logical: keywordNumber, source: "not an encoding", decoded: node, memo: memo}
	if ctx.matches(gate, keywordNumber, 0, len(keywordNumber)) || !memo.inspectionIncomplete() {
		t.Fatal("unavailable source map silently became clean")
	}
	encoded := hex.EncodeToString([]byte("account3333333333333333"))
	graph = newKeywordDecodeSources(encoded)
	node = graph.add(encoded, "account3333333333333333", encodingHex)
	graph.budget.used = maxDecodeTotalBytes
	memo = &decodingMemo{keywordBudget: graph.budget}
	ctx = keywordCandidateContext{alternatives: []*keywordDecodeSource{node}, memo: memo, source: encoded}
	// A real decoded keyword still proves acceptance without raw-map recovery.
	if !ctx.matches(gate, node.text, len("account"), len(node.text)) {
		t.Fatal("available logical context was discarded")
	}
	for _, tc := range []struct {
		source, decoded, encoding      string
		start, end, wantStart, wantEnd int
	}{
		{"33:33", "33", encodingHex, 0, 2, 0, 5},
		{`\u0033\u0033`, "33", encodingJSONUnicode, 0, 1, 0, 6},
		{"%2533%2533", "33", encodingURL, 0, 1, 0, 5},
		{"&#51;&#51;", "33", encodingHTML, 0, 1, 0, 5},
	} {
		offsets := keywordDecodeOffsets(tc.source, tc.decoded, tc.encoding)
		if len(offsets) != len(tc.decoded) || offsets[tc.start].start != tc.wantStart || offsets[tc.end-1].end != tc.wantEnd {
			t.Errorf("mapping %s: %+v", tc.encoding, offsets)
		}
	}
}

func TestDLPKeywordsHarmlessCorpus(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	for _, text := range []string{
		"reference " + keywordNumber,
		"revision 0123456789abcdef0123456789abcdef01234567",
		"request 00000000-1111-2222-3333-444444444444",
		"row,3333333333333333,0,1,2",
		"const sample={value:3333333333333333};",
		"+sample=3333333333333333\n",
		strings.Repeat("ordinary documentation ", 1000) + keywordNumber,
		base64.StdEncoding.EncodeToString([]byte("reference " + keywordNumber)),
	} {
		if result := sc.ScanTextForDLP(t.Context(), text); keywordFound(result) {
			t.Fatalf("unlabeled corpus produced custom finding: %+v", result)
		}
	}
	// A nearby label can corroborate harmless numbers; it does not prove secrecy.
	if !keywordFound(sc.ScanTextForDLP(t.Context(), "account "+keywordNumber)) {
		t.Fatal("labeled numeric positive control was hidden")
	}
}

func TestDLPKeywordsDistinctProducingPaths(t *testing.T) {
	value := "identifier_" + keywordNumber
	first := hex.EncodeToString([]byte(value))
	second := base64.StdEncoding.EncodeToString([]byte(value))
	graph := newKeywordDecodeSources(first)
	node := graph.add(first, value, encodingHex)
	graph.nodes[second] = &keywordDecodeSource{text: second, owner: graph}
	if got := graph.add(second, value, encodingBase64); got != node || len(node.variants) != 1 {
		t.Fatal("second producing path was discarded")
	}
	rule := config.DLPPattern{Name: keywordPattern, Regex: `identifier_[0-9]{16}`, Keywords: []string{"account"}}
	gate, err := rule.CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	memo := &decodingMemo{keywordBudget: graph.budget}
	ctx := keywordCandidateContext{alternatives: []*keywordDecodeSource{node}, source: first + strings.Repeat(" ", 100) + "account " + second, memo: memo}
	if !ctx.matches(gate, value, 0, len(value)) {
		t.Fatal("unlabeled producing path hid a labeled producing path")
	}
	if memo.inspectionIncomplete() {
		t.Fatal("complete source paths reported incomplete")
	}
}

func TestDLPKeywordsQueryProjection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = []config.DLPPattern{{Name: keywordPattern, Regex: `identifier_[0-9]{16}`, Keywords: []string{"account"}}}
	sc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"?p=account%20identifier_33333333&q=33333333", true},
		{"?p=reference%20identifier_33333333&q=33333333", false},
		{"?p=account" + strings.Repeat("%20", 100) + "identifier_33333333&q=33333333", false},
	} {
		u, err := url.Parse("https://api.vendor.example/" + tc.query)
		if err != nil {
			t.Fatal(err)
		}
		result, _ := sc.checkDLP(u)
		if got := strings.Contains(result.Reason, keywordPattern); got != tc.want {
			t.Fatalf("projection finding=%v want=%v: %+v", got, tc.want, result)
		}
	}
}

func TestDLPKeywordsScannerRejectsInvalidProgrammaticConfig(t *testing.T) {
	for _, rule := range []config.DLPPattern{
		{Name: keywordPattern, Regex: `[0-9]{16}`, Keywords: []string{"ab"}},
		{Name: keywordPattern, Regex: `[0-9]{16}`, Keywords: []string{"account", "ACCOUNT"}},
		{Name: keywordPattern, Regex: `[0-9]{16}`, KeywordWindow: new(50)},
		{Name: keywordPattern, Regex: `[0-9]{16}`, Keywords: []string{"account"}, KeywordWindow: new(0)},
	} {
		cfg := config.Defaults()
		cfg.DLP.Patterns = []config.DLPPattern{rule}
		sc, err := New(cfg)
		if sc != nil {
			sc.Close()
		}
		if err == nil {
			t.Fatal("scanner activated invalid keyword policy")
		}
	}
}

func TestDLPKeywordsMetadataBudgetWithoutCandidate(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	var b strings.Builder
	for i := range 5000 {
		_, _ = fmt.Fprintf(&b, "documentationword%d ", i)
	}
	result := sc.ScanTextForDLP(t.Context(), b.String())
	if HasInspectionLimit(result.Matches) || result.Incomplete {
		t.Fatalf("unused keyword context exhausted a clean scan: %+v", result)
	}
	if keywordFound(result) {
		t.Fatal("harmless corpus produced a custom finding")
	}
}

// Tag characters also spell emoji flag subdivisions. Their decoded views must
// keep source coordinates, so ordinary text neither refuses nor over-matches.
func TestDLPKeywordsUnicodeTagContext(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	tags := func(s string) string {
		var b strings.Builder
		for _, c := range s {
			b.WriteRune(0xe0000 + c)
		}
		return b.String()
	}
	flag := "\U0001F3F4" + tags("gbeng") + "\U000E007F"
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"flag without keyword", "Go " + flag + " fans! reference " + keywordNumber, false},
		{"flag with keyword", "Go " + flag + " fans! account " + keywordNumber, true},
		{"flag between distant keyword", "account, see notes for the " + flag + " supporters club annual meeting agenda; ref " + keywordNumber, false},
		{"hidden number without keyword", "x " + strings.Repeat("y ", 50) + tags(keywordNumber), false},
		{"hidden number beyond window", "account" + strings.Repeat(" ", 100) + tags(keywordNumber), false},
		{"hidden number near keyword", "account " + tags(keywordNumber), true},
		{"hidden keyword and number", tags("account " + keywordNumber), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := sc.ScanTextForDLP(t.Context(), tc.text)
			if got := keywordFound(result); got != tc.want {
				t.Fatalf("got=%v want=%v: %+v", got, tc.want, result)
			}
			if HasInspectionLimit(result.Matches) {
				t.Fatalf("context incomplete: %+v", result)
			}
		})
	}
}

func TestKeywordTagAndSegmentOffsets(t *testing.T) {
	source := "a\U000E0001\U000E0062\xff\U000E007Fc"
	decoded := "ab\xffc"
	offsets := keywordTagOffsets(source, decoded)
	want := []keywordByteSpan{{0, 1}, {5, 9}, {9, 10}, {14, 15}}
	if len(offsets) != len(want) {
		t.Fatalf("offsets=%v want %v", offsets, want)
	}
	for i := range want {
		if offsets[i] != want[i] {
			t.Fatalf("offsets=%v want %v", offsets, want)
		}
	}
	if keywordTagOffsets(source, "abc") != nil {
		t.Fatal("mismatched tag decode was mapped")
	}
	if got := keywordSegmentOffsets("ab cd ef", "cd"); len(got) != 2 || got[0] != (keywordByteSpan{3, 4}) {
		t.Fatalf("unique segment offsets=%v", got)
	}
	for _, tc := range []struct{ source, segment string }{{"cd cd", "cd"}, {"aaa", "aa"}, {"ab", "x"}, {"ab", ""}} {
		if keywordSegmentOffsets(tc.source, tc.segment) != nil {
			t.Fatalf("ambiguous or absent segment %q in %q was mapped", tc.segment, tc.source)
		}
	}
}
