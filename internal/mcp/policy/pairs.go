// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"path"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// maxPairwiseTokens caps token count for exhaustive O(n²) pairwise matching.
// Kept at 64 to bound worst-case regex work (~4K pairs × rules).
// Higher values create DoS risk (256 tokens = ~2M regex matches).
// It matches maxPairwiseSplitFields in the MCP input scanner.
const maxPairwiseTokens = 64

// maxPairAnchorLen is the longest token, other than an option, that anchors
// pairs for a pattern with no required literal text. Command words and
// values such as 777 are short; the operands that make a command long are
// mostly paths and longer values.
const maxPairAnchorLen = 24

// maxPairChecks bounds the pairs one pattern checks in an argument list longer
// than maxPairwiseTokens. It equals the exhaustive pair count at
// maxPairwiseTokens, so a long list never costs more pair checks than the
// longest list checked exhaustively.
const maxPairChecks = maxPairwiseTokens * (maxPairwiseTokens - 1)

// argView is one view of the argument tokens. When the arguments are one
// shell command string that splits cleanly (see commandSegments), segments
// holds the tokens of each command in it, and pairs are formed only within a
// command. Otherwise segments is nil and the whole list is one command.
// unsplit is set when the arguments are one string that commandSegments
// could not split, so commands in it cannot be told apart.
type argView struct {
	tokens      []string
	joined      string
	segments    [][]string
	unsplit     bool
	plain       bool
	inputKnown  string // direct xargs utility whose input is proved on raw input
	checkXargs  bool
	interpreted bool              // added option view; cannot erase original uncertainty
	folded      map[string]string // request-local folds of original tokens and joined views
	// findPaths caches findPathsOnly(segments) for a plain view; it does not
	// depend on the pattern. nil means not computed.
	findPaths [][]string
	// xargsFree proves no token can name xargs, so unresolvedXargs is false
	// for every pattern. false means not proved.
	xargsFree bool
}

// literalArgTokens returns the submitted strings unmodified, each as one
// token, and their space-joined form.
func literalArgTokens(args []string) ([]string, string) {
	return args, strings.Join(args, " ")
}

// buildArgViews retains the primary, alt, baseline, and literal views, and adds
// command-option interpretations where they differ. Adding an interpretation
// must not erase a spelling that an existing configured rule matches.
func buildArgViews(args []string) []argView {
	segs, plain := splitCommands(args)
	inputKnown := knownXargsInput(args)
	unsplit := len(args) == 1 && segs == nil
	norms := []struct {
		fn  func(string) string
		pre *strings.Replacer
	}{
		{normalize.ForMatching, policyPreNormalize},
		{normalize.ForPolicy, policyPreNormalize},
		{normalize.ForMatching, nil},
	}
	views := make([]argView, 0, 2*len(norms)+1)
	// add keeps the first of identical views. matchArgViewSet skips a view the
	// same as an earlier one, so dropping it here only saves the work of
	// building and comparing it for every rule.
	add := func(v argView) {
		if slices.ContainsFunc(views, func(prev argView) bool { return sameArgView(prev, v) }) {
			return
		}
		if v.plain && v.segments != nil {
			v.findPaths = findPathsOnly(v.segments)
		}
		// unresolvedXargs needs a word whose base name is exactly xargs, and
		// xargsBoundaries only inserts spaces, so such a word is a substring.
		v.xargsFree = !slices.ContainsFunc(v.tokens, func(t string) bool { return strings.Contains(t, "xargs") })
		views = append(views, v)
	}
	for _, n := range norms {
		tokens, joined := normalizeArgTokensUnexpanded(args, n.fn, n.pre)
		v := argView{tokens: tokens, joined: joined, unsplit: unsplit, plain: plain, inputKnown: inputKnown, checkXargs: true}
		switch {
		case len(segs) == 1:
			v.segments = [][]string{tokens}
		case len(segs) > 1:
			v.segments = make([][]string, 0, len(segs))
			for _, seg := range segs {
				t, _ := normalizeArgTokensUnexpanded([]string{seg}, n.fn, n.pre)
				v.segments = append(v.segments, t)
			}
		}
		// The interpretation is a function of the original tokens.
		if slices.ContainsFunc(views, func(prev argView) bool { return !prev.interpreted && sameArgView(prev, v) }) {
			continue
		}
		add(v)
		expanded := v
		var unknownGit bool
		expanded.tokens, unknownGit = normalizeLineOptions(v.tokens)
		expanded.joined = strings.Join(expanded.tokens, " ")
		if v.segments != nil {
			expanded.segments = make([][]string, 0, len(v.segments))
			for _, seg := range v.segments {
				if len(v.segments) == 1 {
					// The only segment is the token list just interpreted.
					expanded.segments = append(expanded.segments, expanded.tokens)
				} else {
					// A non-builtin Git subcommand anywhere on the line makes every
					// command's destructive readings visible to the pairs it forms.
					t, _ := normalizeOptions(seg, unknownGit)
					expanded.segments = append(expanded.segments, t)
				}
			}
		}
		if !sameArgView(v, expanded) {
			expanded.interpreted = true
			add(expanded)
		}
	}
	tokens, joined := literalArgTokens(args)
	add(argView{tokens: tokens, joined: joined, inputKnown: inputKnown, checkXargs: true})
	folded := make(map[string]string)
	for i := range views {
		for _, token := range views[i].tokens {
			if _, ok := folded[token]; !ok {
				folded[token] = foldString(token)
			}
		}
		if _, ok := folded[views[i].joined]; !ok {
			folded[views[i].joined] = foldString(views[i].joined)
		}
		views[i].folded = folded
	}
	return views
}

// commandSegments splits a single shell command string into the parts that
// pairs are formed within. It cuts at &&, ||, ;, | and newlines outside
// quotes, then joins back what one command can hand to another:
//   - a whole pipeline (a | b | c) stays one part, as any stage can pass
//     its input on to a command that runs it;
//   - a part that writes a file (> f, >> f, tee f) is joined with each later
//     part that names that file (< f, xargs -a f, cat f, --opt=f).
//
// Joined parts keep their order. A match that still spans parts is not
// dropped: matchArgView reports it as an incomplete check.
//
// It returns nil, meaning the arguments are matched as one list, when there
// is not exactly one string, when the string uses expansion or escapes
// ($, backticks, backslashes, parentheses, braces) that normalization may
// rewrite, or when a quote is left open. Separate argument values are not
// split, because a tool may run them without a shell.
func commandSegments(args []string) []string {
	segs, _ := splitCommands(args)
	return segs
}

// splitCommands is commandSegments. plain reports that each quote it saw was
// one the shell reads as a quote: the string has no comment (a # that starts
// a word), no here-document (<<) and no line break inside quotes. A quote
// character in a comment or a here-document is text to the shell, so the
// lines after it may be commands that the quote tracking here took as
// quoted.
func splitCommands(args []string) (_ []string, plain bool) {
	if len(args) != 1 || strings.ContainsAny(args[0], "$`\\(){}") {
		return nil, false
	}
	plain = true
	s := args[0]
	type piece struct {
		start, end int
		afterPipe  bool
	}
	var pieces []piece
	start, afterPipe := 0, false
	cut := func(end, width int, pipe bool) {
		pieces = append(pieces, piece{start, end, afterPipe})
		start, afterPipe = end+width, pipe
	}
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			if c == '\n' {
				plain = false
			}
			continue
		}
		next := byte(0)
		if i+1 < len(s) {
			next = s[i+1]
		}
		switch {
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || strings.IndexByte(" \t\n;|&", s[i-1]) >= 0):
			plain = false
		case c == '<' && next == '<':
			plain = false
		case c == ';' || c == '\n':
			cut(i, 1, false)
		case c == '&' && next == '&':
			cut(i, 2, false)
			i++
		case c == '|' && next == '|':
			cut(i, 2, false)
			i++
		case c == '|' && next == '&':
			cut(i, 2, true)
			i++
		case c == '|':
			cut(i, 1, true)
		}
	}
	if quote != 0 {
		return nil, false
	}
	pieces = append(pieces, piece{start, len(s), afterPipe})

	// Whole pipelines.
	type span struct{ start, end int }
	var cmds []span
	for _, p := range pieces {
		if p.afterPipe && len(cmds) > 0 {
			cmds[len(cmds)-1].end = p.end
			continue
		}
		if strings.TrimSpace(s[p.start:p.end]) == "" {
			continue
		}
		cmds = append(cmds, span{p.start, p.end})
	}

	// File hand-offs.
	group := make([]int, len(cmds))
	find := func(i int) int {
		for group[i] != i {
			group[i] = group[group[i]]
			i = group[i]
		}
		return i
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra > rb {
			ra, rb = rb, ra
		}
		group[rb] = ra
	}
	writer := make(map[string]int)
	for i, c := range cmds {
		group[i] = i
		words := shellWords(s[c.start:c.end])
		refs := fileNames(fileRefs(words))
		reads := false
		for _, ref := range refs {
			if w, ok := writer[ref]; ok {
				union(w, i)
				reads = true
			}
		}
		written := writtenFiles(words)
		if reads {
			// A command that names a file written earlier may copy,
			// move or link it to any other file it names.
			written = append(written, operandFiles(words)...)
		}
		for _, f := range fileNames(written) {
			if w, ok := writer[f]; ok {
				union(w, i)
			} else {
				writer[f] = i
			}
		}
	}
	var segs []string
	at := make(map[int]int)
	for i, c := range cmds {
		r := find(i)
		if k, ok := at[r]; ok {
			segs[k] += " ; " + s[c.start:c.end]
			continue
		}
		at[r] = len(segs)
		segs = append(segs, s[c.start:c.end])
	}
	return segs, plain
}

// shellWords splits a command into words with quote marks removed, so
// 2>>'/tmp/a' and /tmp/a name the same file. It is only used to find file
// names shared between commands.
func shellWords(command string) []string {
	words := strings.Fields(command)
	for i, w := range words {
		words[i] = quoteMarks.Replace(w)
	}
	return words
}

var quoteMarks = strings.NewReplacer(`'`, "", `"`, "")

// outRedirectRe matches an output redirection, with the file name attached
// in group 1 when there is one: >f, >>f, 2>f, &>f, >|f.
var outRedirectRe = regexp.MustCompile(`^(?:[0-9]+|&)?(?:>>?|>\|)&?(.*)$`)

// writtenFiles returns the files a command writes with an output redirection
// or with tee.
func writtenFiles(words []string) []string {
	var out []string
	tee := false
	for i, w := range words {
		if m := outRedirectRe.FindStringSubmatch(w); m != nil {
			switch {
			case m[1] != "":
				out = append(out, m[1])
			case i+1 < len(words):
				out = append(out, words[i+1])
			}
			continue
		}
		switch {
		case w == "|" || w == "|&":
			tee = false
		case path.Base(w) == "tee":
			tee = true
		case tee && !strings.HasPrefix(w, "-"):
			out = append(out, w)
		}
	}
	return out
}

// fileNames returns names with each one's cleaned path (./a is a, /tmp//a
// is /tmp/a) added after it.
func fileNames(names []string) []string {
	out := make([]string, 0, 2*len(names))
	for _, n := range names {
		out = append(out, n)
		if c := path.Clean(n); c != n && n != "" {
			out = append(out, c)
		}
	}
	return out
}

// operandFiles returns the words of a command, after its name, that may name
// a file: each word that is not an option or a redirection, and the value of
// an --option=f or of=f.
func operandFiles(words []string) []string {
	var out []string
	for i, w := range words {
		if i == 0 || redirectTokenRe.MatchString(w) || w == "|" || w == "|&" {
			continue
		}
		if _, v, ok := strings.Cut(w, "="); ok {
			if v != "" {
				out = append(out, v)
			}
			continue
		}
		if !strings.HasPrefix(w, "-") {
			out = append(out, w)
		}
	}
	return out
}

// fileRefs returns the names a command may read a file by: each word, a word
// after an input redirection (<f), and the value of an --option=f.
func fileRefs(words []string) []string {
	out := make([]string, 0, len(words))
	for _, w := range words {
		out = append(out, w)
		if r := strings.TrimLeft(w, "0123456789"); strings.HasPrefix(r, "<") {
			out = append(out, strings.TrimLeft(r, "<"))
		}
		if _, v, ok := strings.Cut(w, "="); ok && v != "" {
			out = append(out, v)
		}
	}
	return out
}

// matchArgViews reports whether pat matches any view. An original match
// resolves the check. A match found only in an added interpretation retains
// any incomplete check from the original views.
//
// A view also matches when pat, or a pattern pat replaced (see
// priorPatterns), matches it as the argument check read it before commands
// in one string were told apart (see priorMatch). Splitting a string into
// commands, or a revised pattern, can then turn a match into an incomplete
// check only where that earlier check found no match either.
func matchArgViews(pat *regexp.Regexp, views ...argView) (matched, incomplete bool) {
	memo := &afterPartsMemo{segs: map[int]*afterPartsSeg{}}
	if !slices.ContainsFunc(views, func(v argView) bool { return v.interpreted }) {
		return matchArgViewSet(pat, memo, views...)
	}
	var original, interpreted []argView
	for _, v := range views {
		if v.interpreted {
			interpreted = append(interpreted, v)
		} else {
			original = append(original, v)
		}
	}
	matched, incomplete = matchArgViewSet(pat, memo, original...)
	if matched {
		return true, false
	}
	// An added interpretation can find a rule, but it cannot clear the
	// original check's on_incomplete_check action. In particular, finding a
	// warn-only rule must not release an original incomplete block.
	moreMatched, moreIncomplete := matchArgViewSet(pat, memo, interpreted...)
	return moreMatched, incomplete || moreIncomplete
}

func matchArgViewSet(pat *regexp.Regexp, memo *afterPartsMemo, views ...argView) (matched, incomplete bool) {
	for i, v := range views {
		if slices.ContainsFunc(views[:i], func(prev argView) bool { return sameArgView(prev, v) }) {
			continue
		}
		m, inc := matchArgView(pat, v, memo)
		if m {
			return true, false
		}
		incomplete = incomplete || inc
	}
	prior := priorPatterns(pat)
	if incomplete {
		// Every view's check covers what priorMatch reads with pat itself,
		// so pat can only match that way when a view came back incomplete.
		prior = append([]*regexp.Regexp{pat}, prior...)
	}
	for _, p := range prior {
		for i, v := range views {
			if slices.ContainsFunc(views[:i], func(prev argView) bool {
				return prev.joined == v.joined && slices.Equal(prev.tokens, v.tokens)
			}) {
				continue
			}
			if priorMatch(p, v.tokens, v.joined, v.folded) {
				return true, false
			}
		}
	}
	return false, incomplete
}

// matchPattern uses the existing required-literal proof before the full regex.
// Missing proof never suppresses a regex check. Word-edge constraints are not
// needed here: substring presence is deliberately broader than a match.
func matchPatternWithFold(pat *regexp.Regexp, text string, folds map[string]string) bool {
	if lits, ok := pairLiterals(pat); ok {
		folded, found := folds[text]
		if !found {
			folded = foldString(text)
		}
		if !slices.ContainsFunc(lits, func(l pairLiteral) bool {
			return strings.Contains(folded, l.text)
		}) {
			return false
		}
	}
	return pat.MatchString(text)
}

// matchPairWithFold reuses token folds while preserving the joined regex input.
func matchPairWithFold(pat *regexp.Regexp, a, c string, folds map[string]string) bool {
	if lits, ok := pairLiterals(pat); ok {
		folded := cachedFold(a, folds) + " " + cachedFold(c, folds)
		if !slices.ContainsFunc(lits, func(l pairLiteral) bool { return strings.Contains(folded, l.text) }) {
			return false
		}
	}
	return pat.MatchString(a + " " + c)
}

// cachedFold also handles tokens introduced by command normalization.
func cachedFold(text string, folds map[string]string) string {
	if folded, ok := folds[text]; ok {
		return folded
	}
	return foldString(text)
}

// sameArgView compares every input to matchArgView, including the provenance
// that decides whether command input can be considered known.
func sameArgView(a, b argView) bool {
	return a.joined == b.joined && a.unsplit == b.unsplit && a.plain == b.plain &&
		a.inputKnown == b.inputKnown && a.checkXargs == b.checkXargs && a.interpreted == b.interpreted &&
		(a.segments == nil) == (b.segments == nil) && slices.Equal(a.tokens, b.tokens) &&
		slices.EqualFunc(a.segments, b.segments, slices.Equal[[]string])
}

// matchArgPattern checks if a regex pattern matches one view of the argument
// tokens (see matchArgViews).
func matchArgPattern(pat *regexp.Regexp, tokens []string, joined string) bool {
	matched, _ := matchArgViews(pat, argView{tokens: tokens, joined: joined})
	return matched
}

// matchArgView checks pat against one view. It uses these strategies:
//  1. Individual tokens (catches self-contained patterns like file paths)
//  2. Each command's tokens joined (fast path for ordered arrays)
//  3. Each command joined without redirections such as 2>&1, and with
//     quoted separators blanked, so they do not break an ordered pattern
//  4. Pairwise token combinations within a command (catches map ordering,
//     where command and flags end up in separate tokens with
//     non-deterministic iteration order)
//
// Up to maxPairwiseTokens tokens, strategy 4 checks every ordered pair. Above
// it, a bounded scan runs (see matchBoundedPairs).
//
// When the view is split into commands and none matches, the whole list is
// checked once more as one command. A match there spans commands: it is not
// reported as a match, but as incomplete, so splitting never turns a match
// into a clean result. incomplete also reports a bounded scan that stopped
// before it covered every pair it needed.
func matchArgView(pat *regexp.Regexp, v argView, memo *afterPartsMemo) (matched, incomplete bool) {
	for _, t := range v.tokens {
		if matchPatternWithFold(pat, t, v.folded) {
			return true, false
		}
	}
	// Input-derived arguments need not occur in the submitted command text.
	// Only a raw, direct, path-preserving handoff can clear this uncertainty.
	incomplete = v.checkXargs && !v.xargsFree && unresolvedXargs(pat, v.tokens) &&
		(v.inputKnown == "" || !isCommandWord(v.inputKnown, leadingWords(pat)))
	exhaustive := len(v.tokens) <= maxPairwiseTokens
	if v.segments == nil {
		m, inc := matchCommand(pat, v.tokens, v.joined, false, exhaustive, &pairBudget{pat: pat, folds: v.folded})
		if !m && v.unsplit && commandAfterPartsShared(pat, [][]string{v.tokens}, memo) {
			// Commands in the string cannot be told apart, so one may
			// hand the words before it to the other.
			return false, true
		}
		return m, inc || incomplete
	}
	b := &pairBudget{pat: pat, folds: v.folded}
	for _, seg := range v.segments {
		m, inc := matchCommand(pat, seg, strings.Join(seg, " "), true, exhaustive, b)
		if m {
			return true, false
		}
		incomplete = incomplete || inc
	}
	// A single segment with the same tokens already received this check, and
	// repeating it is only identical when blanking (see cleanCommandTokens)
	// had nothing to replace. A token with ; | or & is read differently by
	// the two checks, so that case keeps the raw one.
	if len(v.segments) != 1 || !slices.Equal(v.segments[0], v.tokens) ||
		slices.ContainsFunc(v.tokens, func(t string) bool { return strings.ContainsAny(t, ";|&") }) {
		if m, inc := matchCommand(pat, v.tokens, v.joined, false, exhaustive, &pairBudget{pat: pat, folds: v.folded}); m || inc {
			return false, true
		}
	}
	paths := v.segments
	switch {
	case v.plain && v.findPaths != nil:
		paths = v.findPaths
	case v.plain:
		paths = findPathsOnly(v.segments)
	}
	if commandAfterPartsShared(pat, paths, memo) {
		return false, true
	}
	return false, incomplete
}

// findWordsUnsafe are find words that print, write or run something other
// than the path names found, read starting points from elsewhere, or end
// the options; a find with any of them keeps every word.
var findWordsUnsafe = []string{
	"-exec", "-execdir", "-ok", "-okdir", "-printf", "-fprintf", "-fprint",
	"-fprint0", "-ls", "-fls", "-files0-from", "-f", "--",
}

// findPathsOnly returns segs with the options and expression words of each
// find command dropped, since find prints only the path names it finds, and
// those start with its starting points, which are kept. segs is returned as
// it is when a find may print anything else or may not be find: when its
// output is joined with its errors, when it has a word in findWordsUnsafe,
// when it is not named find, /bin/find or /usr/bin/find at the start of a
// command, or when a word outside the arguments of such a find may change
// what find runs (see mayRedefineFind). Those arguments are given to find,
// not run by the shell, so a starting point such as . or a test such as
// -path is not taken as such a word.
func findPathsOnly(segs [][]string) [][]string {
	seen := false
	for _, seg := range segs {
		start, args := true, false
		for _, t := range seg {
			if strings.Contains(t, ">&") || strings.Contains(t, "&>") || strings.Contains(t, "|&") ||
				strings.ContainsAny(strings.TrimRight(t, ";|&"), ";|&") {
				return segs
			}
			switch {
			case start && isFindCommand(t):
				seen, args = true, true
			case args:
				// One of find's arguments.
			default:
				args = false
				if mayRedefineFind(t, foldString(t)) {
					return segs
				}
			}
			start = endsCommand(t)
			if start {
				args = false
			}
		}
	}
	if !seen {
		return segs
	}
	out := make([][]string, len(segs))
	for i, seg := range segs {
		out[i] = dropFindWords(seg)
	}
	return out
}

// findLeadingOption matches the options GNU and BSD find take before the
// starting points; -D takes a value.
var findLeadingOption = regexp.MustCompile(`^(?:-[HLPEXdsx]+|-O[0-9]*|-D)$`)

// findRedefiners are shell words that may change which program or function
// a later find runs.
var findRedefiners = []string{
	"alias", "hash", "enable", "eval", "source", ".", "function", "declare",
	"typeset", "export", "readonly", "local", "builtin", "set", "shopt",
}

// mayRedefineFind reports whether word t, f folded, may change what a later
// find runs: a word that names PATH or find (other than as the command), or
// one of findRedefiners.
func mayRedefineFind(t, f string) bool {
	w := handOffWord(t)
	foldedWord := foldString(w)
	switch {
	case strings.Contains(f, foldString("path")):
		return true
	case strings.Contains(f, foldString("find")) && !isFindCommand(t):
		return true
	}
	return slices.ContainsFunc(findRedefiners, func(r string) bool { return foldString(r) == foldedWord })
}

// isFindWordUnsafe reports whether w is in findWordsUnsafe, case-folded.
func isFindWordUnsafe(w string) bool {
	return slices.ContainsFunc(findWordsUnsafe, func(u string) bool { return foldString(u) == foldString(w) })
}

// isFindCommand reports whether t names the find program.
func isFindCommand(t string) bool {
	return slices.Contains([]string{"find", "/bin/find", "/usr/bin/find"}, t)
}

// dropFindWords is findPathsOnly for one command list.
func dropFindWords(seg []string) []string {
	out := make([]string, 0, len(seg))
	start := true
	for i := 0; i < len(seg); i++ {
		t := seg[i]
		if !start || !isFindCommand(t) {
			out = append(out, t)
			start = endsCommand(t)
			continue
		}
		end := i + 1 // find's words are seg[i+1:end], through the one that ends it
		for end < len(seg) {
			end++
			if endsCommand(seg[end-1]) {
				break
			}
		}
		out = append(out, t)
		out = append(out, findKept(seg[i+1:end])...)
		i = end - 1
		start = true
	}
	return out
}

// findKept returns the words of find's arguments args that may reach its
// output: every word when one is unsafe, otherwise the starting points,
// redirections and the operator that ends the command.
func findKept(args []string) []string {
	for _, a := range args {
		w := strings.TrimRight(a, ";|&")
		if strings.ContainsAny(w, ";|&") || isFindWordUnsafe(handOffWord(a)) {
			return args
		}
	}
	var kept []string
	j := 0
	for ; j < len(args); j++ { // options before the starting points
		w := handOffWord(args[j])
		if !findLeadingOption.MatchString(w) {
			break
		}
		if w == "-D" && j+1 < len(args) {
			j++ // its value is kept as if it were a starting point
			kept = append(kept, args[j])
		}
	}
	expr := false
	for ; j < len(args); j++ {
		a := args[j]
		w := handOffWord(a)
		// A , before the expression is a starting point to GNU find, and so
		// is a lone -, or a word with a glob character (* ? [) that the shell
		// may expand to one.
		option := strings.HasPrefix(w, "-") && w != "-" && !strings.ContainsAny(w, "*?[")
		if !expr && (option || w == "!" || w == "(") {
			expr = true
		}
		switch {
		case w == "":
			kept = append(kept, a)
		case !expr:
			kept = append(kept, a)
		case a != strings.TrimRight(a, ";|&"):
			kept = append(kept, a[len(strings.TrimRight(a, ";|&")):])
		}
	}
	return kept
}

// endsCommand reports whether t ends a command with ; | or &.
func endsCommand(t string) bool {
	return t != strings.TrimRight(t, ";|&")
}

// commandAfterParts reports whether a command word of pat (see
// leadingWords) comes after words that, given to it, make pat match with at
// least two of them, as when one command hands its output to xargs. A match
// that needs only one such word is left to the pair check. A command run by
// xargs gets the words handed to it after its own, so when words follow the
// command, pat is also checked against the command, the words after it, then
// the words before it; that match counts when the words after it alone do
// not make it. It checks each
// command of segs, where pipelines and file hand-offs are already joined, at
// each command word in it. When the command words of pat cannot be
// worked out within the bounds of leadingWords, every word is taken as one,
// and a command of more than maxPairwiseTokens words is reported as is.
func commandAfterParts(pat *regexp.Regexp, segs [][]string) bool {
	return commandAfterPartsShared(pat, segs, nil)
}

// afterPartsMemo shares commandAfterParts results between the views of one
// argument check, all for the same pattern. Views usually differ in a few words
// (see buildArgViews), so the text checked before a command is often the same.
type afterPartsMemo struct {
	segs map[int]*afterPartsSeg // by command index, from the first view checked
}

// afterPartsSeg records, for one command, the words handed on and the result
// of matching pat against a command word and the words before it, by position.
type afterPartsSeg struct {
	handed []string
	before map[int]bool
}

// commandAfterPartsShared is commandAfterParts, reusing results recorded in
// memo. A result is reused only at a position whose command word and every
// word before it equal those recorded, so the text matched is the same.
func commandAfterPartsShared(pat *regexp.Regexp, segs [][]string, memo *afterPartsMemo) bool {
	words, over := leadingWordsBounded(pat)
	if len(words) == 0 && !over {
		return false
	}
	for k, seg := range segs {
		if over && len(seg) > maxPairwiseTokens {
			return true
		}
		var handed []string
		var at []int
		for _, t := range seg {
			w := handOffWord(t)
			if len(handed) > 0 && (over || isCommandWord(t, words) || isCommandWord(w, words)) {
				at = append(at, len(handed))
			}
			if w != "" {
				handed = append(handed, w)
			} else if len(at) > 0 && at[len(at)-1] == len(handed) {
				at = at[:len(at)-1]
			}
		}
		// before is always handed[:i] and at increases, so oneWordMatch for a
		// command word only needs the words added since its last position.
		type oneWordScan struct {
			upto    int
			matched bool
		}
		scans := make(map[string]*oneWordScan)
		var prev, record *afterPartsSeg
		same := 0 // handed[:same] equals prev.handed[:same]
		if memo != nil && len(at) > 0 {
			if prev = memo.segs[k]; prev != nil {
				for same < len(handed) && same < len(prev.handed) && handed[same] == prev.handed[same] {
					same++
				}
			} else {
				record = &afterPartsSeg{handed: handed, before: make(map[int]bool, len(at))}
				memo.segs[k] = record
			}
		}
		for _, i := range at {
			command, before := handed[i], handed[:i]
			s := scans[command]
			if s == nil {
				s = &oneWordScan{}
				scans[command] = s
			}
			if !s.matched {
				s.matched = oneWordMatch(pat, command, handed[s.upto:i])
				s.upto = i
			}
			if s.matched {
				continue
			}
			matched, known := false, false
			if prev != nil && i < same {
				matched, known = prev.before[i]
			}
			if !known {
				matched = pat.MatchString(command + " " + strings.Join(before, " "))
			}
			if record != nil {
				record.before[i] = matched
			}
			if matched {
				return true
			}
			if i+1 == len(handed) {
				continue
			}
			own := strings.Join(handed[i:], " ")
			if !pat.MatchString(own) && pat.MatchString(own+" "+strings.Join(before, " ")) {
				return true
			}
		}
	}
	return false
}

// isCommandWord reports whether t, or its base name, is one of words
// (case-folded, see foldString).
func isCommandWord(t string, words []string) bool {
	base := path.Base(t)
	return slices.ContainsFunc(words, func(w string) bool {
		return strings.EqualFold(t, w) || strings.EqualFold(base, w)
	})
}

// leadingWordsCache holds leadingWordsBounded results by pattern source.
var leadingWordsCache sync.Map // string -> leadWordsResult

// leadWordsResult is a leadingWordsBounded result.
type leadWordsResult struct {
	words []string
	over  bool
}

// maxLeadingWords bounds the words leadingWords returns for one pattern.
const maxLeadingWords = 16

// leadingWords returns the literal text, case-folded, that every match of
// pat starts with, one entry per alternative (chmod and chown for
// ch(?:mod|own)...), or nil when a match can start some other way.
func leadingWords(pat *regexp.Regexp) []string {
	words, _ := leadingWordsBounded(pat)
	return words
}

// leadingWordsBounded is leadingWords, and also reports over when the words
// could not be worked out within maxLeadWordSteps steps, or there are more
// than maxLeadingWords of them. The words are nil then. A pattern a match
// of which can start with something other than a literal gets nil words and
// is not over.
func leadingWordsBounded(pat *regexp.Regexp) (words []string, over bool) {
	if cached, hit := leadingWordsCache.Load(pat.String()); hit {
		r := cached.(leadWordsResult)
		return r.words, r.over
	}
	if re, err := syntax.Parse(pat.String(), syntax.Perl); err == nil {
		seq := []*syntax.Regexp{re.Simplify()}
		steps := maxLeadWordSteps
		words = leadWords(seq, "", &steps)
		if steps < 0 {
			// Cut short: walk again without the word limit, to tell a
			// pattern that can start with a non-literal from one that is
			// too big to work out.
			steps = maxLeadWordSteps
			w := leadWalk{steps: &steps, memo: map[string][]string{}}
			words = w.words(seq, "")
		}
		slices.Sort(words)
		words = slices.Compact(words)
		switch {
		case steps >= 0 && slices.Contains(words, ""):
			words = nil
		case steps < 0 || len(words) > maxLeadingWords:
			words, over = nil, true
		}
	}
	leadingWordsCache.Store(pat.String(), leadWordsResult{words, over})
	return words, over
}

// maxLeadWordSteps bounds the work leadingWords does for one pattern; a
// pattern that needs more, or has more than maxLeadingWords ways to start,
// gets no words, and commandAfterParts then takes every word as one.
const maxLeadWordSteps = 4096

// leadWords is leadingWords for the sequence seq after prefix. steps is
// counted down once per part worked out, and more for a long seq; a part
// seen before with the same prefix is not worked out again. An optional or repeated part before the
// first word is either left out or taken once; a repeated part taken once
// ends the word. Inside a word, such a part ends it. More than
// maxLeadingWords ways to start cut the walk short.
func leadWords(seq []*syntax.Regexp, prefix string, steps *int) []string {
	w := leadWalk{steps: steps, memo: map[string][]string{}, cut: true}
	return w.words(seq, prefix)
}

// leadWalk holds the state of one leadWords walk. A walk that runs out of
// steps, or is cut, leaves steps at -1, and its words are a cut list then.
type leadWalk struct {
	steps *int
	memo  map[string][]string // part and prefix -> words
	cut   bool                // stop at more than maxLeadingWords ways
}

// words is leadWords for seq after prefix.
func (w *leadWalk) words(seq []*syntax.Regexp, prefix string) []string {
	// A long seq costs more steps, for the key below.
	if *w.steps -= len(seq) / 64; *w.steps < 0 {
		*w.steps = -1
		return []string{""}
	}
	var key strings.Builder
	key.WriteString(prefix)
	for _, x := range seq {
		fmt.Fprintf(&key, "\x00%p", x)
	}
	if got, seen := w.memo[key.String()]; seen && *w.steps >= 0 {
		return got
	}
	if *w.steps--; *w.steps < 0 {
		return []string{""}
	}
	got := w.part(seq, prefix)
	w.memo[key.String()] = got
	return got
}

// part is words for seq after prefix, worked out from its first part.
func (w *leadWalk) part(seq []*syntax.Regexp, prefix string) []string {
	if len(seq) == 0 {
		return []string{prefix}
	}
	x, rest := seq[0], seq[1:]
	switch x.Op {
	case syntax.OpEmptyMatch:
		return w.words(rest, prefix)
	case syntax.OpBeginText, syntax.OpBeginLine, syntax.OpWordBoundary:
		if prefix == "" {
			return w.words(rest, prefix)
		}
	case syntax.OpLiteral:
		return w.words(rest, prefix+foldString(string(x.Rune)))
	case syntax.OpCapture:
		return w.words(slices.Concat(x.Sub[:1], rest), prefix)
	case syntax.OpConcat:
		return w.words(slices.Concat(x.Sub, rest), prefix)
	case syntax.OpAlternate:
		return w.of(x.Sub, rest, prefix)
	case syntax.OpQuest:
		if prefix == "" {
			return w.of([]*syntax.Regexp{emptyRegexp, x.Sub[0]}, rest, prefix)
		}
	case syntax.OpStar:
		if prefix == "" {
			return w.merge(slices.Concat(w.words(rest, prefix), w.words(x.Sub[:1], prefix)))
		}
	case syntax.OpPlus:
		if prefix == "" {
			return w.words(x.Sub[:1], prefix)
		}
	}
	return []string{prefix}
}

// emptyRegexp matches the empty string.
var emptyRegexp = &syntax.Regexp{Op: syntax.OpEmptyMatch}

// of is words for each of alts followed by rest.
func (w *leadWalk) of(alts, rest []*syntax.Regexp, prefix string) []string {
	var out []string
	for _, sub := range alts {
		out = append(out, w.words(slices.Concat([]*syntax.Regexp{sub}, rest), prefix)...)
		if w.cut && len(out) > maxLeadingWords {
			*w.steps = -1 // a cut list is not every word
			return out
		}
	}
	return w.merge(out)
}

// merge drops repeated words from out when the walk is not cut, so that
// the same word reached many ways is kept once.
func (w *leadWalk) merge(out []string) []string {
	if w.cut {
		return out
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// oneWordMatch reports whether pat matches command followed by any one of
// words.
func oneWordMatch(pat *regexp.Regexp, command string, words []string) bool {
	for _, w := range words {
		if pat.MatchString(command + " " + w) {
			return true
		}
	}
	return false
}

// handOffWord returns t as a word another command could read, or "" for a
// redirection or a bare ; | & operator. Operator marks at its ends are cut.
func handOffWord(t string) string {
	if redirectTokenRe.MatchString(t) {
		return ""
	}
	return strings.Trim(t, ";|&")
}

// matchCommand checks pat against the tokens of one command: joined, joined
// without redirections, then in pairs, every pair when exhaustive is set and
// otherwise within b (see matchBoundedPairs).
func matchCommand(pat *regexp.Regexp, tokens []string, joined string, blank, exhaustive bool, b *pairBudget) (matched, incomplete bool) {
	if matchPatternWithFold(pat, joined, b.folds) {
		return true, false
	}
	if cleaned, changed := cleanCommandTokens(tokens, blank); changed && matchPatternWithFold(pat, strings.Join(cleaned, " "), b.folds) {
		return true, false
	}
	if here, ok := hereStringData(tokens); ok && matchPatternWithFold(pat, strings.Join(here, " "), b.folds) {
		return true, false
	}
	if exhaustive {
		for i, a := range tokens {
			for j, c := range tokens {
				if i != j && matchPairWithFold(pat, a, c, b.folds) {
					return true, false
				}
			}
		}
		return false, false
	}
	found, complete := boundedPairs(b, tokens)
	return found, !found && !complete
}

// redirectTokenRe matches a shell redirection token: 2>&1, &>/dev/null,
// >>out.log, <in, or a bare > or 2>.
var redirectTokenRe = regexp.MustCompile(`^(?:[0-9]+|&)?(?:>>?|<|>\|)`)

// cleanCommandTokens drops redirection tokens from one command. When blank is
// set, the command came from commandSegments, so any ; | or & left in a token
// was quoted, and it is replaced with _ so an ordered pattern can read past
// it. changed reports whether anything was dropped or replaced.
func cleanCommandTokens(tokens []string, blank bool) (cleaned []string, changed bool) {
	cleaned = make([]string, 0, len(tokens))
	for _, t := range tokens {
		if redirectTokenRe.MatchString(t) {
			changed = true
			continue
		}
		if blank && strings.ContainsAny(t, ";|&") {
			t = strings.Map(func(r rune) rune {
				if r == ';' || r == '|' || r == '&' {
					return '_'
				}
				return r
			}, t)
			changed = true
		}
		cleaned = append(cleaned, t)
	}
	return cleaned, changed
}

// hereStringData returns tokens with each here-string (<<<word) replaced by
// its word, the input the command reads, and other redirections dropped. ok
// is false when there is no here-string with a word attached.
func hereStringData(tokens []string) (out []string, ok bool) {
	out = make([]string, 0, len(tokens))
	for _, t := range tokens {
		if data, found := strings.CutPrefix(t, "<<<"); found {
			if data != "" {
				out, ok = append(out, data), true
			}
			continue
		}
		if !redirectTokenRe.MatchString(t) {
			out = append(out, t)
		}
	}
	return out, ok
}

// pairBudget counts pattern checks against maxPairChecks.
type pairBudget struct {
	pat    *regexp.Regexp
	checks int
	folds  map[string]string
}

// tryPair checks a pair unless the budget is spent; more is false once it is.
func (b *pairBudget) tryPair(a, c string) (found, more bool) {
	if b.checks >= maxPairChecks {
		return false, false
	}
	b.checks++
	return matchPairWithFold(b.pat, a, c, b.folds), true
}

// matchBoundedPairs is the pairwise view of an argument list longer than
// maxPairwiseTokens, run within each command in segs and within
// maxPairChecks pattern checks in total.
//
// When every match of pat must contain one of a set of literal strings (see
// pairLiterals), a pair can only match if one of its tokens holds one (see literalIn),
// so only pairs with such a token are checked, and the scan is complete when it
// checks all of them. Otherwise each distinct anchor (an option, or a short
// token with no path separator) is paired with each other distinct token, and
// the scan is complete only when no token was left out.
//
// complete is false when the scan stopped at the check limit or left a token
// out, so a caller can tell a no-match that covered every pair it needed from
// one that did not.
func matchBoundedPairs(pat *regexp.Regexp, segs [][]string) (matched bool, checks int, complete bool) {
	b := &pairBudget{pat: pat}
	for _, seg := range segs {
		found, segComplete := boundedPairs(b, seg)
		if found {
			return true, b.checks, true
		}
		if !segComplete {
			return false, b.checks, false
		}
	}
	return false, b.checks, true
}

// boundedPairs is matchBoundedPairs for one command, within b.
func boundedPairs(b *pairBudget, tokens []string) (found, complete bool) {
	if lits, ok := pairLiterals(b.pat); ok {
		return literalPairs(b, distinctByPriority(tokens), lits)
	}
	return anchoredPairs(b, tokens)
}

// literalPairs checks, in both orders, every pair in tokens that includes a
// token holding one of lits (see literalIn). Tokens that are a literal, or
// whose base name is (rm, /bin/rm), are paired first, so other tokens that
// merely hold the text cannot use up the check limit before them.
func literalPairs(b *pairBudget, tokens []string, lits []pairLiteral) (found, complete bool) {
	has := make([]bool, len(tokens))
	var exact, rest []int
	for i, t := range tokens {
		h, e := literalIn(t, lits)
		has[i] = h
		switch {
		case e:
			exact = append(exact, i)
		case h:
			rest = append(rest, i)
		}
	}
	done := make([]bool, len(tokens))
	for _, i := range slices.Concat(exact, rest) {
		a := tokens[i]
		for j, c := range tokens {
			if i == j || (has[j] && done[j]) {
				continue
			}
			f, more := b.tryPair(a, c)
			if f || !more {
				return f, more
			}
			if f, more = b.tryPair(c, a); f || !more {
				return f, more
			}
		}
		done[i] = true
	}
	return false, true
}

// anchoredPairs pairs each distinct anchor with each other distinct token, in
// both orders: anchors with each other first, then anchors with the rest.
func anchoredPairs(b *pairBudget, tokens []string) (found, complete bool) {
	anchors, others, dropped := splitPairTokens(tokens)
	for i, a := range anchors {
		for j, c := range anchors {
			if i == j {
				continue
			}
			f, more := b.tryPair(a, c)
			if f || !more {
				return f, more && !dropped
			}
		}
	}
	for _, a := range anchors {
		for _, c := range others {
			f, more := b.tryPair(a, c)
			if f || !more {
				return f, more && !dropped
			}
			if f, more = b.tryPair(c, a); f || !more {
				return f, more && !dropped
			}
		}
	}
	return false, !dropped
}

// pairTier orders tokens for pairing: options first, then other short tokens
// without a path separator, then the rest.
func pairTier(t string) int {
	switch {
	case strings.HasPrefix(t, "-"):
		return 0
	case len(t) <= maxPairAnchorLen && !strings.ContainsAny(t, `/\`):
		return 1
	default:
		return 2
	}
}

// distinctByPriority returns the distinct tokens, options first, then short
// tokens, then the rest, each group in first-seen order.
func distinctByPriority(tokens []string) []string {
	seen := make(map[string]struct{}, len(tokens))
	var tiers [3][]string
	for _, t := range tokens {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		tier := pairTier(t)
		tiers[tier] = append(tiers[tier], t)
	}
	return slices.Concat(tiers[0], tiers[1], tiers[2])
}

// splitPairTokens returns the distinct tokens split into anchors (options,
// then short tokens with no path separator) and the rest. It keeps at most
// maxPairwiseTokens anchors and maxPairChecks/2 others, so the scan stays
// bounded however long the list is; an anchor past its limit is kept as one
// of the rest when there is room. dropped reports that a distinct token was
// left out.
func splitPairTokens(tokens []string) (anchors, others []string, dropped bool) {
	const maxAnchors = maxPairwiseTokens
	const maxOthers = maxPairChecks / 2
	for _, t := range distinctByPriority(tokens) {
		switch {
		case pairTier(t) < 2 && len(anchors) < maxAnchors:
			anchors = append(anchors, t)
		case len(others) < maxOthers:
			others = append(others, t)
		default:
			return anchors, others, true
		}
	}
	return anchors, others, false
}

// pairLiteralCache holds pairLiterals results by pattern source.
var pairLiteralCache sync.Map // string -> pairLiteralSet

type pairLiteralSet struct {
	lits []pairLiteral
	ok   bool
}

// pairLiteral is text, case-folded (see foldString), that a match must
// contain. wordStart is set when the pattern puts a word boundary or the
// start of a line right before the text, and wordEnd when only a non-word
// character or the end of the text can follow it. A token can then supply
// the text only where it is not preceded (wordStart) or followed (wordEnd)
// by a word character.
type pairLiteral struct {
	text               string
	wordStart, wordEnd bool
}

// pairLiterals returns literals such that every match of pat contains at
// least one of them. ok is false when there is no such set, or when a
// literal holds white space and so could span the space between the two
// tokens of a pair.
func pairLiterals(pat *regexp.Regexp) (lits []pairLiteral, ok bool) {
	if cached, hit := pairLiteralCache.Load(pat.String()); hit {
		set := cached.(pairLiteralSet)
		return set.lits, set.ok
	}
	var set pairLiteralSet
	if re, err := syntax.Parse(pat.String(), syntax.Perl); err == nil {
		set.lits, set.ok = requiredLiterals(re.Simplify(), nil, nil)
		if set.ok && slices.ContainsFunc(set.lits, func(l pairLiteral) bool {
			return l.text == "" || strings.IndexFunc(l.text, unicode.IsSpace) >= 0
		}) {
			set = pairLiteralSet{}
		}
	}
	pairLiteralCache.Store(pat.String(), set)
	return set.lits, set.ok
}

// requiredLiterals returns literals such that every match of re contains at
// least one of them, or ok false when it finds none. before holds what the
// pattern matches right before re, nearest first, and after what it matches
// right after re, in order; nil means nothing known.
func requiredLiterals(re *syntax.Regexp, before, after []*syntax.Regexp) (lits []pairLiteral, ok bool) {
	switch re.Op {
	case syntax.OpLiteral:
		fold := re.Flags&syntax.FoldCase != 0
		first, last := re.Rune[0], re.Rune[len(re.Rune)-1]
		return []pairLiteral{{
			text:      foldString(string(re.Rune)),
			wordStart: edgeNonWord(before, false, wordRune(first, fold)),
			wordEnd:   edgeNonWord(after, true, wordRune(last, fold)),
		}}, true
	case syntax.OpCapture:
		return requiredLiterals(re.Sub[0], before, after)
	case syntax.OpPlus:
		return requiredLiterals(re.Sub[0], nil, nil)
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiterals(re.Sub[0], nil, nil)
		}
	case syntax.OpConcat:
		// Any one part's set will do; prefer the one whose shortest literal
		// is longest, as it is the most selective.
		best := -1
		for i, sub := range re.Sub {
			prev := slices.Clone(re.Sub[:i])
			slices.Reverse(prev)
			l, subOK := requiredLiterals(sub, slices.Concat(prev, before), slices.Concat(re.Sub[i+1:], after))
			if !subOK {
				continue
			}
			if shortest := shortestLen(l); shortest > best {
				lits, ok, best = l, true, shortest
			}
		}
		return lits, ok
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			l, subOK := requiredLiterals(sub, before, after)
			if !subOK {
				return nil, false
			}
			lits = append(lits, l...)
		}
		return lits, true
	}
	return nil, false
}

// edgeNonWord reports whether seq, read forward (or backward, with seq
// nearest first), must start with a non-word character, or with the start
// (backward) or end (forward) of the text or a line. edgeWord is whether the
// character on the other side is always a word character, which makes a
// word boundary next to it count.
func edgeNonWord(seq []*syntax.Regexp, forward, edgeWord bool) bool {
	steps := 0
	return edgeNonWordSteps(seq, forward, edgeWord, &steps)
}

// maxEdgeSteps bounds the work edgeNonWord does on one pattern; past it the
// answer is false, which only means a token is not narrowed by the edge.
const maxEdgeSteps = 10000

func edgeNonWordSteps(seq []*syntax.Regexp, forward, edgeWord bool, steps *int) bool {
	*steps++
	if len(seq) == 0 || *steps > maxEdgeSteps {
		return false
	}
	re, rest := seq[0], seq[1:]
	switch re.Op {
	case syntax.OpEmptyMatch:
		return edgeNonWordSteps(rest, forward, edgeWord, steps)
	case syntax.OpWordBoundary:
		return edgeWord
	case syntax.OpBeginLine, syntax.OpBeginText:
		return !forward
	case syntax.OpEndLine, syntax.OpEndText:
		return forward
	case syntax.OpCharClass:
		return classNonWord(re.Rune)
	case syntax.OpLiteral:
		r := re.Rune[0]
		if !forward {
			r = re.Rune[len(re.Rune)-1]
		}
		return nonWordRune(r, re.Flags&syntax.FoldCase != 0)
	case syntax.OpCapture:
		return edgeNonWordSteps(slices.Concat(re.Sub[:1], rest), forward, edgeWord, steps)
	case syntax.OpConcat:
		subs := slices.Clone(re.Sub)
		if !forward {
			slices.Reverse(subs)
		}
		return edgeNonWordSteps(slices.Concat(subs, rest), forward, edgeWord, steps)
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !edgeNonWordSteps(slices.Concat([]*syntax.Regexp{sub}, rest), forward, edgeWord, steps) {
				return false
			}
		}
		return true
	case syntax.OpPlus:
		return edgeNonWordSteps(slices.Concat(re.Sub[:1], rest), forward, edgeWord, steps)
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return edgeNonWordSteps(slices.Concat(re.Sub[:1], rest), forward, edgeWord, steps)
		}
		return edgeNonWordSteps(slices.Concat(re.Sub[:1], rest), forward, edgeWord, steps) && edgeNonWordSteps(rest, forward, edgeWord, steps)
	case syntax.OpStar, syntax.OpQuest:
		return edgeNonWordSteps(slices.Concat(re.Sub[:1], rest), forward, edgeWord, steps) && edgeNonWordSteps(rest, forward, edgeWord, steps)
	}
	return false
}

// isWordByte reports whether r is a word character for \b: [0-9A-Za-z_].
func isWordByte(r rune) bool {
	return r == '_' || ('0' <= r && r <= '9') || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z')
}

// wordRune reports whether r, and with fold every rune it matches under
// case folding, is a word character.
func wordRune(r rune, fold bool) bool {
	return allFolds(r, fold, isWordByte)
}

// nonWordRune reports whether r, and with fold every rune it matches under
// case folding, is not a word character.
func nonWordRune(r rune, fold bool) bool {
	return allFolds(r, fold, func(c rune) bool { return !isWordByte(c) })
}

func allFolds(r rune, fold bool, f func(rune) bool) bool {
	if !f(r) {
		return false
	}
	if fold {
		for c := unicode.SimpleFold(r); c != r; c = unicode.SimpleFold(c) {
			if !f(c) {
				return false
			}
		}
	}
	return true
}

// classNonWord reports whether a character class (as lo, hi range pairs)
// holds no word character.
func classNonWord(ranges []rune) bool {
	for i := 0; i+1 < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		for _, w := range [][2]rune{{'0', '9'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}} {
			if lo <= w[1] && hi >= w[0] {
				return false
			}
		}
	}
	return true
}

// literalIn reports whether token t holds one of lits at a place a match
// could use (see pairLiteral), and whether t, or its base name, is a
// literal.
func literalIn(t string, lits []pairLiteral) (has, exact bool) {
	orig := []rune(t)
	folded := []rune(foldString(t))
	base := foldString(path.Base(t))
	whole := string(folded)
	for _, l := range lits {
		if l.text == whole || l.text == base {
			return true, true
		}
		lr := []rune(l.text)
		for i := 0; i+len(lr) <= len(folded); i++ {
			if !slices.Equal(folded[i:i+len(lr)], lr) {
				continue
			}
			end := i + len(lr)
			if l.wordStart && i > 0 && isWordByte(orig[i-1]) {
				continue
			}
			if l.wordEnd && end < len(orig) && isWordByte(orig[end]) {
				continue
			}
			has = true
			break
		}
	}
	return has, false
}

func shortestLen(lits []pairLiteral) int {
	n := -1
	for _, l := range lits {
		if n < 0 || len(l.text) < n {
			n = len(l.text)
		}
	}
	return n
}

// foldString maps each rune to the smallest rune that matches it under
// case-insensitive matching, so a folded string contains a folded literal
// whenever a (?i) pattern could match that literal in the original.
func foldString(s string) string {
	return strings.Map(func(r rune) rune {
		// ASCII letters have the uppercase rune as their least fold, even
		// when their fold cycle also contains a non-ASCII rune (K and S).
		if r < unicode.MaxASCII+1 {
			if r >= 'a' && r <= 'z' {
				return r - ('a' - 'A')
			}
			return r
		}
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < least {
				least = f
			}
		}
		return least
	}, s)
}
