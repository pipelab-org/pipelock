// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math/rand"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Expressions chosen independently of the optimizer's own fixtures. Each one
// targets a soundness assumption: fold orbits that change byte width, word
// assertions beside multibyte runes, optional and lazy segments, unbounded
// classes outside the run alphabet, path explosion and invalid UTF-8.
var optimizerDifferentialExpressions = []string{
	`(?i)\bkey\s*:\s*secret\b`,
	`(?i)ignore\s+(?:all\s+)?previous\s+instructions`,
	`alpha(?:\s+beta)?\s+gamma`,
	`(?s)begin.{0,40}finish`,
	`begin.{0,40}finish`,
	`(?:foo|ba[rz])\W{1,3}qux`,
	`(?i)straße\s+ẞig`,
	`\bфильтр\b\s+обход`,
	`(?i)фильтр\s+обход`,
	`[a-z]+@[a-z]+\.example`,
	`zeta[^;]*omega`,
	`zeta\S+eta\S+theta`,
	`(?m)^override\s+policy$`,
	`(?i)k[e3]y\s{0,3}=\s{0,3}"[^"]{2,16}"`,
	`abc(?:def|xyz)*ghi`,
	`(?:aa|bb)cc(?:dd|ee)ff.{0,3}zz(?:gg|hh)ii`,
	`(?U)lazy.{1,30}tail`,
	`alpha\p{Greek}{2,5}omega`,
	`(?i)σοφία\s+λόγος`,
	`(?i)ǆungla\s+tail`,
	`\x{FFFD}marker`,
	`\x{212A}elvin\s+mark`,
	`(?i)skip\b.{0,6}\bkeys`,
	`(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|alpha1|bravo1|charlie1|delta1|echo1|foxtrot1|golf1|hotel1|india1|juliet1|kilo1|lima1|mike1|november1|oscar1|papa1|quebec1|romeo1|sierra1|tango1|uniform1|victor1|whiskey1|xray1|yankee1|zulu1|aaa2|bbb2|ccc2|ddd2|eee2|fff2|ggg2|hhh2|iii2|jjj2|kkk2|lll2|mmm2|nnn2|ooo2|ppp2|qqq2|rrr2|sss2|ttt2|uuu2|vvv2|www2|xxx2|yyy2|zzz2)\s+(?:sink|drain)`,
	`(?i)pre(?:fix)?\B\w{0,4}\bsuf`,
	`send\s+(?:the\s+)?(?:api\s+)?keys?\s+to\b`,
	`x{2,}yz.{0,5}end`,
	`(?:\bstart|^begin)\s+run`,
	`a.b.c.d.efgh`,
	`alpha[0-9]+[a-c]+;omega`,
	`item\s+[0-9]+:value`,
	`tag[a-f]+\s+[0-9]+#end`,
}

// One sample per expression; an empty sample marks an expression that
// cannot match (its word assertions contradict), which must stay clean.
var optimizerDifferentialPositives = []string{
	"x\u212Aey : ſecret ", "IGNORE  all previous instructions", "alpha beta\tgamma", "begin\n\nxx finish",
	"begin -- finish", "baz;-qux", "STRAẞE ßig", "", "ФИЛЬТР ОБХОД", "abc@def.example",
	"zeta xx yy omega", "zetaXetaYtheta", "\noverride policy\n", `K3Y = "abcd"`, "abcdefxyzghi",
	"bbccddff..zzhhii", "lazy xx tail tail", "alphaαβγomega", "ΣΟΦΊΑ λόγοσ", "ǅUNGLA tail", "\xffmarker",
	"\u212Aelvin mark", "ſkip -x\u212Aeys", "zulu1  drain", "", "send the api keys to ", "xxxyz..end",
	" start run", "a-b-c-d-efgh", "alpha123abc;omega", "item  42:value", "tagabc 12#end",
}

// Fragments and fillers that should not complete any expression alone.
var optimizerBenignTokens = []string{
	"lorem", "ipsum", "data", "value", "alph", "gamm", "secre", "instruc", "previou", "fini", "omeg", "thet",
	"overrid", "polic", "markr", "elvi", "drai", "sin", "lazi", "tai", "efg", "ghj", "~~~~", "0123", "{", "}",
	"(", ")", "=>", "alpha12", "ab;omeg", "item ", "42", ":valu", "tagab", "#en", "\u200b", "\u0301", "日本語", "\xff", "\xc3", "Kſ", "ẞ", "ς", "Ǆ", "\ufffd", "αβ", "фил",
}

var optimizerDifferentialTokens = []string{
	"key", "KEY", "Key", "\u212Aey", "\u212AEY", "secret", "ſecret", "SECRET", ":", " : ", "\t:\t",
	"ignore", "IGNORE", "all", "previous", "instructions", "ınstructions", "alpha", "beta", "gamma",
	"begin", "finish", "foo", "bar", "baz", "qux", "straße", "STRASSE", "STRAẞE", "ẞig", "ßig", "sig",
	"фильтр", "ФИЛЬТР", "обход", "ОБХОД", "@", ".example", "zeta", "omega", "eta", "theta",
	"override", "policy", "k3y", "kEy", "=", "\"abcdef\"", "\"x\"", "abc", "def", "xyz", "ghi", "aa", "bb",
	"cc", "dd", "ee", "ff", "zz", "gg", "hh", "ii", "lazy", "tail", "αβγ", "ΑΒΓΔΕ", "σοφία", "ΣΟΦΊΑ", "σοφίας",
	"λόγος", "ΛΌΓΟΣ", "λόγοσ", "ǆungla", "Ǆungla", "ǅungla", "\xff", "\xc3", "\xe2\x84", "\ufffd", "marker",
	"\u212Aelvin", "Kelvin", "mark", "skip", "keys", "\u212Aeys", "ſkip", "twenty", "zulu1", "zzz2", "sink",
	"drain", "pre", "prefix", "suf", "send", "the", "api", "to", "xx", "xxx", "yz", "end", "start", "run",
	"a", "b", "c", "d", "efgh", "alpha1", "abc", ";omega", "item", ":value", "tagabc", "#end", "\u200b", "\u0301", "日本語", "_", "-", "0", "42",
}

var optimizerDifferentialSeparators = []string{" ", "  ", "\t", "\n", "\r\n", ";", "-", "_", "", ".", ",", "\u00a0", "\v", " ; ", "|"}

func optimizerDifferentialText(rnd *rand.Rand, size int) string {
	var b strings.Builder
	for b.Len() < size {
		switch rnd.Intn(10) {
		case 0:
			// Long runs grow measured repeat widths.
			b.WriteString(strings.Repeat(optimizerDifferentialSeparators[rnd.Intn(len(optimizerDifferentialSeparators))], rnd.Intn(300)))
		case 1:
			b.WriteString(strings.Repeat("~", rnd.Intn(600)))
		default:
			b.WriteString(optimizerDifferentialTokens[rnd.Intn(len(optimizerDifferentialTokens))])
			b.WriteString(optimizerDifferentialSeparators[rnd.Intn(len(optimizerDifferentialSeparators))])
		}
	}
	return b.String()
}

func optimizerBenignText(rnd *rand.Rand, size int) string {
	var b strings.Builder
	for b.Len() < size {
		if rnd.Intn(12) == 0 {
			b.WriteString(strings.Repeat(optimizerDifferentialSeparators[rnd.Intn(len(optimizerDifferentialSeparators))], rnd.Intn(200)))
			continue
		}
		b.WriteString(optimizerBenignTokens[rnd.Intn(len(optimizerBenignTokens))])
		b.WriteString(optimizerDifferentialSeparators[rnd.Intn(len(optimizerDifferentialSeparators))])
	}
	return b.String()
}

// Replace every match span until the text is clean for the given patterns.
func optimizerSanitize(patterns []*compiledPattern, text string) string {
	for range 32 {
		matches := matchPatternsAgainst(patterns, text)
		if len(matches) == 0 {
			return text
		}
		out := []byte(text)
		for _, p := range patterns {
			for _, loc := range p.re.FindAllStringIndex(text, -1) {
				for i := loc[0]; i < loc[1]; i++ {
					out[i] = '~'
				}
			}
		}
		text = string(out)
	}
	return text
}

func optimizerPlant(rnd *rand.Rand, text string) string {
	sample := ""
	for sample == "" {
		sample = optimizerDifferentialPositives[rnd.Intn(len(optimizerDifferentialPositives))]
	}
	at := rnd.Intn(len(text) + 1)
	if rnd.Intn(2) == 0 {
		return text[:at] + sample + text[at:]
	}
	end := min(len(text), at+len(sample))
	return text[:at] + sample + text[end:]
}

func optimizerDifferentialMutate(rnd *rand.Rand, text string) string {
	out := []byte(text)
	for range 1 + rnd.Intn(6) {
		if len(out) == 0 {
			break
		}
		at := rnd.Intn(len(out))
		token := optimizerDifferentialTokens[rnd.Intn(len(optimizerDifferentialTokens))]
		switch rnd.Intn(3) {
		case 0:
			out = append(out[:at], append([]byte(token), out[at:]...)...)
		case 1:
			end := min(len(out), at+1+rnd.Intn(8))
			out = append(out[:at], out[end:]...)
		default:
			end := min(len(out), at+len(token))
			out = append(out[:at], append([]byte(token), out[end:]...)...)
		}
	}
	return string(out)
}

func optimizerIterations(t *testing.T, fallback int) int {
	t.Helper()
	if raw := os.Getenv("PIPELOCK_RESPONSE_DIFF_ITERATIONS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	return fallback
}

// The matcher-level oracle runs the production prefilter, literal program,
// chain windows, delta windows and shared buffers against FindAll on the
// whole view. Sequential memos share buffers exactly as the decode walk does.
func TestResponseOptimizerMatcherDifferential(t *testing.T) {
	seed := int64(20261122)
	if raw := os.Getenv("PIPELOCK_RESPONSE_DIFF_SEED"); raw != "" {
		seed, _ = strconv.ParseInt(raw, 10, 64)
	}
	rnd := rand.New(rand.NewSource(seed)) // #nosec G404 -- deterministic, reproducible differential corpus.
	patterns := make([]*compiledPattern, len(optimizerDifferentialExpressions))
	for i, expression := range optimizerDifferentialExpressions {
		patterns[i] = memoTestPattern("optimizer "+strconv.Itoa(i), expression)
	}
	for i, sample := range optimizerDifferentialPositives {
		if sample != "" && !patterns[i].re.MatchString(sample) {
			t.Fatalf("positive sample %d does not describe %q", i, optimizerDifferentialExpressions[i])
		}
	}
	pf := newResponsePreFilter(patterns)
	program := responseMatchingProgram(pf)
	if program == nil {
		t.Fatal("no literal program")
	}
	iterations := optimizerIterations(t, 60)
	var buffers responseMatchingBuffers
	chainWindows := &responseChainWindowMemo{}
	positives := 0
	for i := range iterations {
		parent := optimizerDifferentialText(rnd, responseMemoMinBytes+rnd.Intn(4*responseMemoMinBytes))
		if rnd.Intn(4) != 0 {
			parent = optimizerSanitize(patterns, parent)
		}
		parentMemo := newResponseMatchMemo(len(parent))
		parentMemo.buffers = &buffers
		parentMemo.chainWindows = chainWindows
		got := parentMemo.matchTransformed(pf, patterns, parent, program, matchingPrimary)
		want := matchPatternsAgainst(patterns, parent)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("iteration %d parent: got %v, want %v", i, got, want)
		}
		if len(want) > 0 {
			positives++
		}
		proof := parentMemo.deltaProof
		deltaParent := &responseDeltaParent{proof: proof, raw: parent}
		deltaParent.text[matchingPrimary], deltaParent.ready[matchingPrimary] = parent, true
		for range 3 {
			child := parent
			if rnd.Intn(3) != 0 {
				child = optimizerPlant(rnd, child)
			}
			if rnd.Intn(2) == 0 {
				child = optimizerDifferentialMutate(rnd, child)
			}
			if len(child) < responseMemoMinBytes {
				continue
			}
			memo := newResponseMatchMemo(len(child))
			memo.buffers = &buffers
			memo.chainWindows = chainWindows
			memo.deltaParent = deltaParent
			got := memo.matchTransformed(pf, patterns, child, program, matchingPrimary)
			want := matchPatternsAgainst(patterns, child)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("iteration %d child: got %v, want %v\nparent matched: %v", i, got, want, matchPatternsAgainst(patterns, parent))
			}
			if len(want) > 0 {
				positives++
			}
		}
	}
	t.Logf("iterations=%d positive views=%d", iterations, positives)
}

// The end-to-end oracle compares complete scan results, including decoded
// views, labels, spans, warn/block classification and incompleteness, with a
// scanner that has no prefilter, literal index, windows, chains or delta.
func TestResponseOptimizerScanDifferential(t *testing.T) {
	seed := int64(4242)
	if raw := os.Getenv("PIPELOCK_RESPONSE_DIFF_SEED"); raw != "" {
		seed, _ = strconv.ParseInt(raw, 10, 64)
	}
	rnd := rand.New(rand.NewSource(seed)) // #nosec G404 -- deterministic, reproducible differential corpus.
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.ResponseScanning.Enabled = true
	for i, expression := range optimizerDifferentialExpressions {
		cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{Name: "Optimizer " + strconv.Itoa(i), Regex: expression})
	}
	type pair struct{ sc, reference *Scanner }
	pairs := map[string]pair{}
	for _, mode := range []string{config.ActionBlock, config.ActionWarn} {
		cfg.PromptInjectionDetection = &config.PromptInjectionDetection{Action: mode}
		sc, reference := MustNew(cfg), MustNew(cfg)
		t.Cleanup(sc.Close)
		t.Cleanup(reference.Close)
		responsePassReference(reference)
		pairs[mode] = pair{sc, reference}
	}
	encoders := []func(string) string{
		func(s string) string { return s },
		func(s string) string {
			var b strings.Builder
			for _, r := range s {
				if r < 0x80 && r > ' ' && rnd.Intn(4) == 0 {
					b.WriteString(`\u00` + strconv.FormatInt(int64(r), 16))
					continue
				}
				b.WriteRune(r)
			}
			return b.String()
		},
		func(s string) string {
			var b strings.Builder
			for _, r := range s {
				if r < 0x80 && r > ' ' && rnd.Intn(4) == 0 {
					b.WriteString("&#" + strconv.Itoa(int(r)) + ";")
					continue
				}
				b.WriteRune(r)
			}
			return b.String()
		},
		func(s string) string {
			var b strings.Builder
			for _, r := range s {
				if r < 0x80 && r > ' ' && rnd.Intn(4) == 0 {
					b.WriteString("%" + strings.ToUpper(strconv.FormatInt(int64(r), 16)))
					continue
				}
				b.WriteRune(r)
			}
			return b.String()
		},
		func(s string) string { return strings.ReplaceAll(s, " ", "<b> </b>") },
	}
	iterations := optimizerIterations(t, 6)
	findings := 0
	for i := range iterations {
		plain := optimizerBenignText(rnd, responseMemoMinBytes+rnd.Intn(3*responseMemoMinBytes))
		// Embed short encoded islands in a large plain page, which produces
		// near-identical decoded views and drives the delta paths.
		var page strings.Builder
		page.WriteString(plain)
		for range 1 + rnd.Intn(4) {
			island := optimizerBenignText(rnd, 20+rnd.Intn(60))
			if rnd.Intn(2) == 0 {
				island = optimizerPlant(rnd, island)
			}
			page.WriteString(encoders[1+rnd.Intn(len(encoders)-1)](island))
			page.WriteString(optimizerBenignText(rnd, 200+rnd.Intn(800)))
		}
		text := page.String()
		for _, mode := range []string{config.ActionBlock, config.ActionWarn} {
			got := pairs[mode].sc.ScanResponse(t.Context(), text)
			want := pairs[mode].reference.ScanResponse(t.Context(), text)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("iteration %d mode %s:\n got clean=%t incomplete=%t err=%q matches=%v warned=%v\nwant clean=%t incomplete=%t err=%q matches=%v warned=%v",
					i, mode, got.Clean, got.InspectionIncomplete, got.ScanError, got.Matches, got.WarnedMatches,
					want.Clean, want.InspectionIncomplete, want.ScanError, want.Matches, want.WarnedMatches)
			}
			if len(got.Matches)+len(got.WarnedMatches) > 0 {
				findings++
				if os.Getenv("PIPELOCK_RESPONSE_DIFF_VERBOSE") != "" {
					for _, m := range append(got.Matches, got.WarnedMatches...) {
						t.Logf("finding %s %q", m.PatternName, m.MatchText)
					}
				}
			}
		}
	}
	t.Logf("iterations=%d results with findings=%d", iterations, findings)
}

// Sparse views are materialized by walking edit records through their bases.
// Both the scanner and any scanner-based reference read the same storage, so
// check it against the plain strings: nested bases, alternate (non-parent)
// bases, arbitrary subranges, and deduplication by exact content.
func TestResponseOptimizerSparseQueueMaterialization(t *testing.T) {
	rnd := rand.New(rand.NewSource(7)) // #nosec G404 -- deterministic property corpus.
	iterations := optimizerIterations(t, 200)
	sparse, nested := 0, 0
	for i := range iterations {
		root := optimizerDifferentialText(rnd, responseMemoMinBytes+rnd.Intn(responseMemoMinBytes))
		queue := newInjectionDecodeQueue(root, false)
		texts := []string{root}
		for range 1 + rnd.Intn(6) {
			base := rnd.Intn(len(texts))
			child := optimizerDifferentialMutate(rnd, texts[base])
			if rnd.Intn(2) == 0 {
				child = optimizerDifferentialMutate(rnd, child)
			}
			digest, duplicate := queue.lookup(child)
			if wantDuplicate := slices.Contains(texts, child); duplicate != wantDuplicate {
				t.Fatalf("iteration %d: duplicate = %t, want %t", i, duplicate, wantDuplicate)
			}
			if duplicate {
				continue
			}
			alignment := alignInjectionDecodeView(queue.decodeView(base), base, child)
			stored, cost := alignment.prepare(child, maxDecodeTotalBytes)
			if cost == 0 {
				stored, _ = queue.prepare(child, maxDecodeTotalBytes, false)
			} else {
				sparse++
				if queue.views[base].edits != nil {
					nested++
				}
			}
			queue.add(stored, injectionDecodeView{text: child}, digest)
			texts = append(texts, child)
		}
		for index, want := range texts {
			if got := queue.decodeView(index).text; got != want {
				t.Fatalf("iteration %d view %d: materialized text differs", i, index)
			}
			for range 8 {
				start := rnd.Intn(len(want) + 1)
				end := start + rnd.Intn(len(want)-start+1)
				var got strings.Builder
				queue.walkViewText(index, start, end, func(part string) bool {
					got.WriteString(part)
					return true
				})
				if got.String() != want[start:end] {
					t.Fatalf("iteration %d view %d range [%d,%d): got %q, want %q", i, index, start, end, got.String(), want[start:end])
				}
			}
			if _, duplicate := queue.lookup(want); !duplicate {
				t.Fatalf("iteration %d view %d: stored view was not found by exact content", i, index)
			}
		}
	}
	if sparse == 0 || nested == 0 {
		t.Fatalf("fixture exercised %d sparse and %d nested sparse views", sparse, nested)
	}
	t.Logf("sparse views=%d nested=%d", sparse, nested)
}
