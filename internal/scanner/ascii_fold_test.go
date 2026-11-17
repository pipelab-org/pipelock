// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestASCIIFoldedRegexpParity(t *testing.T) {
	for _, expression := range []string{
		`(?i)secret\s*=\s*[A-Za-z0-9]{8,}`, `(?i)(k|s)+foo[A-Z]+`, `(?i)ſKÉa`,
		`(?i)\b(foo|bar)\b`, `(?im)^((?:foo|bar)?bAz+)$`, `(?is)a.*?z`,
		`(?i)(?P<first>AB|A)(?P<second>B?)`, `(?i)[^A-Za-z]+ABC`,
		`(?i)[A-Z\x{100}-\x{200}]+foo`, `(?i)foo(?:bar){2,4}`, `(?i)(?:|foo)bar`,
		`(?i)[\p{Greek}]+foo`, `(?i)foo\Bbar`, `(?i)foo\z`,
	} {
		t.Run(expression, func(t *testing.T) {
			original := regexp.MustCompile(expression)
			folded := compileASCIIFoldedRegexp(expression)
			if folded == nil {
				t.Fatal("eligible grammar rejected")
			}
			tree, err := syntax.Parse(expression, syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			inputs := []string{"", "SeCrEt = aBCDefGH", "KſkKsSS", "ſKÉA", "ΣFOO𐀀", "FOO BAR baZZ", "AAB", "\xff\x00FOOBAR\xfe", "foo\nBAR\nz", "\ufffdFOObar"}
			for i := range 64 {
				sample := asciiFoldExample(tree, i)
				inputs = append(inputs, sample, "before: "+sample+"; after", sample+"\n"+sample)
			}
			for _, input := range inputs {
				assertASCIIFoldParity(t, original, folded, input)
			}
		})
	}
}

func assertASCIIFoldParity(t *testing.T, original, folded *regexp.Regexp, input string) {
	t.Helper()
	want := original.FindAllStringSubmatchIndex(input, -1)
	got := folded.FindAllStringSubmatchIndex(lowerASCIIForRegexp(input), -1)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q on %q: indices %v want %v", original.String(), input, got, want)
	}
}

// The examples come from the original AST, independently of the rewrite.
func asciiFoldExample(tree *syntax.Regexp, choice int) string {
	switch tree.Op {
	case syntax.OpLiteral:
		var out strings.Builder
		for _, r := range tree.Rune {
			if tree.Flags&syntax.FoldCase != 0 {
				for range choice % 3 {
					r = unicode.SimpleFold(r)
				}
			}
			out.WriteRune(r)
		}
		return out.String()
	case syntax.OpCharClass:
		at := 2 * (choice % (len(tree.Rune) / 2))
		r := tree.Rune[at]
		if choice%2 != 0 {
			r = tree.Rune[at+1]
		}
		return string(r)
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return "!"
	case syntax.OpCapture:
		return asciiFoldExample(tree.Sub[0], choice)
	case syntax.OpConcat:
		var out strings.Builder
		for i, sub := range tree.Sub {
			out.WriteString(asciiFoldExample(sub, choice+i))
		}
		return out.String()
	case syntax.OpAlternate:
		return asciiFoldExample(tree.Sub[choice%len(tree.Sub)], choice/len(tree.Sub))
	case syntax.OpStar, syntax.OpQuest:
		if choice%2 == 0 {
			return ""
		}
		return asciiFoldExample(tree.Sub[0], choice)
	case syntax.OpPlus:
		return strings.Repeat(asciiFoldExample(tree.Sub[0], choice), 1+choice%3)
	case syntax.OpRepeat:
		count := tree.Min
		if tree.Max < 0 || tree.Max > tree.Min {
			count++
		}
		return strings.Repeat(asciiFoldExample(tree.Sub[0], choice), count)
	default:
		return ""
	}
}

func TestASCIIFoldedRegexpRejectsCaseSensitiveGrammar(t *testing.T) {
	for _, expression := range []string{"(", "plain", `(?i:foo)(?-i:[A-Z])`, `(?i:foo)(?-i:bar)`, `(?i:foo)(?-i:[^a-z])`, `(?i:foo)(?-i:[\p{Lu}])`, `[0-9]+`} {
		t.Run(expression, func(t *testing.T) {
			if got := compileASCIIFoldedRegexp(expression); got != nil {
				t.Fatalf("unsafe or unchanged grammar admitted: %q", got)
			}
		})
	}
}

func TestASCIIFoldedRegexpConfiguredParity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	admitted := 0
	for _, pattern := range append(append([]*compiledPattern{}, sc.dlpPatterns...), sc.core.dlpPatterns...) {
		t.Run(pattern.name, func(t *testing.T) {
			if pattern.asciiFoldedRE == nil {
				return
			}
			admitted++
			tree, err := syntax.Parse(pattern.re.String(), syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			for i := range 32 {
				sample := asciiFoldExample(tree, i)
				for _, input := range []string{sample, "ordinary prose; " + sample + "; done", strings.ToUpper(sample), "\xff" + sample + "\xfe"} {
					assertASCIIFoldParity(t, pattern.re, pattern.asciiFoldedRE, input)
				}
			}
		})
	}
	if admitted == 0 {
		t.Fatal("no configured rule uses the optimization")
	}
}

func TestASCIIFoldedPreparedViewKeepsOriginalValidators(t *testing.T) {
	p := &compiledPattern{re: regexp.MustCompile(`(?i)mark[a-z]{4}`), validate: func(candidate string) bool { return candidate == "MaRkAbCd" }}
	p.prepareASCIIFoldedRegexp()
	text := "markabcd then MaRkAbCd"
	var input asciiFoldedInput
	start, end, ok := p.matchSpanInPreparedView(text, text, &input, nil)
	if !ok || text[start:end] != "MaRkAbCd" {
		t.Fatalf("original validator bytes lost: start=%d end=%d ok=%v", start, end, ok)
	}
	if !input.ready {
		t.Fatal("prepared matching did not use the folded input")
	}
	got := input.text
	p.matchSpanInPreparedView(text, text, &input, nil)
	if got != input.text {
		t.Fatal("one loop changed its borrowed view")
	}
	p.re = regexp.MustCompile(`then`)
	p.validate = nil
	var fallback asciiFoldedInput
	start, end, ok = p.matchSpanInPreparedView(text, text, &fallback, nil)
	if !ok || text[start:end] != "then" || fallback.ready {
		t.Fatal("replaced expression reused a stale compiled alternative")
	}
}

func TestASCIIFoldedPreparationKeepsSpecializedPaths(t *testing.T) {
	for _, kind := range []string{"boundary", "keywords", "overlap"} {
		t.Run(kind, func(t *testing.T) {
			p := &compiledPattern{re: regexp.MustCompile(`(?i)mark[a-z]{4}`)}
			switch kind {
			case "boundary":
				p.withoutLeftBoundary = p.re
			case "overlap":
				p.wifOverlapRetry = true
			case "keywords":
				matcher, err := (config.DLPPattern{Keywords: []string{"account"}}).CompileKeywords()
				if err != nil {
					t.Fatal(err)
				}
				p.keywords = matcher
			}
			p.prepareASCIIFoldedRegexp()
			if p.asciiFoldedRE != nil {
				t.Fatal("specialized path received an alternative")
			}
		})
	}
	for _, input := range []string{"", "already lower", "UPPER", "a\xffZKſ"} {
		got := lowerASCIIForRegexp(input)
		if len(got) != len(input) {
			t.Fatal("byte offsets changed")
		}
		for i := range len(input) {
			want := input[i]
			if want >= 'A' && want <= 'Z' {
				want += 'a' - 'A'
			}
			if got[i] != want {
				t.Fatalf("byte %d changed incorrectly", i)
			}
		}
	}
}

func TestASCIIFoldedPreparedViewKeepsAdmission(t *testing.T) {
	p := &compiledPattern{re: regexp.MustCompile(`(?i)mark=foo`), requiresEquals: true}
	p.prepareASCIIFoldedRegexp()
	var input asciiFoldedInput
	if _, _, ok := p.matchSpanInPreparedView("MARK FOO", "MARK FOO", &input, nil); ok || input.ready {
		t.Fatal("necessary admission was bypassed")
	}
	if _, _, ok := p.matchSpanInPreparedView("absent=bar", "absent=bar", &input, nil); ok || !input.ready {
		t.Fatal("finding-free prepared matching did not inspect the borrowed view")
	}
}

func TestASCIIFoldedPairedNormalizationKeepsMemoBookkeeping(t *testing.T) {
	sc := decodeRunScanner(t)
	text := "K|MaRK1234|" + "AKIA" + "IOSFODNN7EXAMPLE"
	for _, shared := range []bool{false, true} {
		for _, full := range []bool{false, true} {
			t.Run(fmt.Sprintf("shared=%v/full=%v", shared, full), func(t *testing.T) {
				makeMemo := func() *decodingMemo {
					m := &decodingMemo{reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true}
					if shared {
						m.shared = &sharedDecodes{}
						if full {
							m.shared.store.retainedBytes = maxDecodeTotalBytes
						}
					} else if full {
						m.retainedBytes = maxDecodeTotalBytes
					}
					m.reassemblyObserve(text)
					t.Cleanup(m.releaseProjection)
					return m
				}
				baseline, paired := makeMemo(), makeMemo()
				want := baseline.matchDecodedCore(sc, text, encodingBase64)
				want = append(want, baseline.matchDecodedFor(sc, text, encodingBase64, textDLPAllPatterns)...)
				var run normalizationRun
				got := paired.matchDecodedKeyWithNormalization(decodedMatchKey{scanner: sc, text: text, encoding: encodingBase64, core: true}, &run)
				got = append(got, paired.matchDecodedForWithNormalization(sc, text, encodingBase64, textDLPAllPatterns, &run)...)
				if !reflect.DeepEqual(got, want) {
					t.Fatal("paired matching changed findings or spans")
				}
				if !shared && (!run.set || !run.loweredReady) {
					t.Fatal("paired normalization did not retain its synchronous transform")
				}
				if a, b := observeDecodeRunState(baseline), observeDecodeRunState(paired); !reflect.DeepEqual(a, b) {
					t.Fatalf("bookkeeping changed: baseline=%+v paired=%+v", a, b)
				}
			})
		}
	}
}

func TestASCIIFoldedNormalizationRunUsesExactSource(t *testing.T) {
	var run normalizationRun
	for _, input := range []string{"KMark", "KMark", "different ſource", "different ſource"} {
		if got := (*decodingMemo)(nil).normalizeWithRun(input, &run); got != normalize.ForDLP(input) {
			t.Fatal("normalization run rebound to a different source")
		}
	}
}

// A run reused for a different source must drop its lowered summary and folded
// input. A stale prefilter summary or folded view would skip a real credential.
func TestASCIIFoldedNormalizationRunClearsBorrowedStateOnSourceChange(t *testing.T) {
	sc := decodeRunScanner(t)
	credential := "ghp_" + strings.Repeat("aB3x", 9)
	first, second := "plain prose only, nothing here", "note: "+credential+" end"
	match := func(memo *decodingMemo, run *normalizationRun, text string) []TextDLPMatch {
		found := memo.matchDecodedKeyWithNormalization(decodedMatchKey{scanner: sc, text: text, encoding: encodingBase64, core: true}, run)
		return append(found, memo.matchDecodedForWithNormalization(sc, text, encodingBase64, textDLPAllPatterns, run)...)
	}
	var run normalizationRun
	local := &decodingMemo{}
	if got := match(local, &run, first); len(got) != 0 || !run.loweredReady {
		t.Fatalf("first source: matches=%v loweredReady=%v", got, run.loweredReady)
	}
	want := match(&decodingMemo{}, &normalizationRun{}, second)
	if len(want) == 0 {
		t.Fatal("fixture no longer carries a finding")
	}
	got := match(local, &run, second)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("source change reused stale borrowed state: got=%+v want=%+v", got, want)
	}
	if run.source != second {
		t.Fatalf("run kept source %q", run.source)
	}
}

func TestASCIIFoldedScannerParity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Prepared marker", Regex: `marker_[A-Za-z]{12}`, Action: config.ActionWarn, Severity: config.SeverityHigh})
	fast, original := MustNew(cfg), MustNew(cfg)
	t.Cleanup(fast.Close)
	t.Cleanup(original.Close)
	disable := func(patterns []*compiledPattern) []*compiledPattern {
		out := make([]*compiledPattern, len(patterns))
		for i, p := range patterns {
			cp := *p
			cp.asciiFoldedRE = nil
			cp.asciiFoldedSource = nil
			out[i] = &cp
		}
		return out
	}
	original.dlpPatterns = disable(original.dlpPatterns)
	core := *original.core
	core.dlpPatterns = disable(core.dlpPatterns)
	original.core = &core
	credential := "ghp_" + strings.Repeat("aB3x", 9)
	for _, input := range []string{
		"ordinary build output: status=ready", "aws_secret_access_key=" + strings.Repeat("qA8/", 10),
		"early decoy password=x then password=" + strings.Repeat("qA8v", 8),
		"MARKER_abcdefghijkl", "marker_abcdefghijk then MARKER_AbCdEfGhIjKl", credential,
		"Kſ|" + credential, "\xff" + credential + "\xfe", base64.StdEncoding.EncodeToString([]byte(credential)),
		"https://api.vendor.example/?token=" + credential,
	} {
		t.Run(fmt.Sprintf("bytes=%d/%x", len(input), sha256.Sum256([]byte(input))), func(t *testing.T) {
			var a, b []string
			fast.SetDLPWarnHook(func(_ context.Context, name, _ string) { a = append(a, name) })
			original.SetDLPWarnHook(func(_ context.Context, name, _ string) { b = append(b, name) })
			got, want := fast.ScanTextForDLP(t.Context(), input), original.ScanTextForDLP(t.Context(), input)
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(a, b) {
				t.Fatalf("findings, spans or warning order changed: got=%+v want=%+v warnings=%v/%v", got, want, a, b)
			}
		})
	}
}
