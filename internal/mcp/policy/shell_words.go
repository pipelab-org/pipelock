// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"regexp"
	"strings"
)

// The word reading is one more rule view of a shell command string: the words
// the shell would produce from expansions whose result the text itself
// decides. Tool policy does not resolve run-time values (a variable set
// elsewhere, the files a wildcard matches); this view reads only what the
// published shell rules fix from the text alone:
//
//   - a parameter expansion still unresolved after resolveShellConstruction
//     reads as unset, which POSIX defines exactly (Shell Command Language,
//     2.6.2 Parameter Expansion): null for $x and ${x}, word for ${x-word},
//     ${x:-word}, ${x=word} and ${x:=word}, null for ${x+word} and the other
//     forms, 0 for ${#x};
//   - brace expansion joins the preamble and postscript to each item (Bash
//     Reference Manual, 3.5.1 Brace Expansion), so {r,}m reads as "rm m";
//   - a bracket expression that lists only literal characters matches exactly
//     one of them (POSIX Shell Command Language, 2.14.1 Patterns Matching a
//     Single Character), so r[m] reads as rm.
//
// A variable set elsewhere may hold any text, and its unset reading is the one
// the text can state. Reading it is the strictest reading of a word the
// expansion splits: r${u}m, rm$u, --for${u}ce. Views are alternatives, so the
// reading adds matches and never removes one from the other views. Wildcards
// (*, ?), ranges, classes and negated brackets name files that exist at run
// time and are left as written.

// maxWordExpansions bounds the words one brace or bracket expansion of a word
// may produce. It equals maxPairwiseTokens, the most tokens the pairwise
// matcher checks exhaustively. A word that would expand further keeps its
// unexpanded spelling in this view; the other views still read it.
const maxWordExpansions = maxPairwiseTokens

// maxParamNesting bounds the passes that resolve nested braced expansions,
// innermost first, such as ${a:-${b}}.
const maxParamNesting = 8

// bracedParamRe matches an innermost braced parameter expansion: an optional
// length (#) or indirection (!) prefix, a name or positional parameter, and
// the rest of the expansion up to its closing brace.
var bracedParamRe = regexp.MustCompile(`\$\{(#?)(!?)([A-Za-z_][A-Za-z0-9_]*|[0-9]+)([^{}]*)\}`)

// bareParamRe matches an unbraced expansion of a name (POSIX XBD 3.216, the
// longest run of name characters) or of positional parameters 1 to 9.
// Special parameters such as $?, $$ and $0 are set by the shell and are left
// as written; $@ and $* are handled by shellPositionalRe.
var bareParamRe = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*|[1-9])`)

// bracketRe matches a bracket expression whose members are only literal
// characters: no negation, range, class, escape or nested bracket.
var bracketRe = regexp.MustCompile(`\[([A-Za-z0-9._~+@%,:=/]{1,8})\]`)

// readShellWords applies the word reading to normalized text. It runs after
// resolveShellConstruction, so assignments the text makes are read first.
func readShellWords(s string) string {
	if strings.ContainsRune(s, '$') {
		s = readUnsetParameters(s)
	}
	if strings.ContainsAny(s, "{[") {
		s = expandWords(s)
	}
	return s
}

// readUnsetParameters replaces each remaining parameter expansion with its
// value when the parameter is unset. IFS is left to shellExpansionRe: the
// shell sets it at startup, and the views read it as a word separator.
func readUnsetParameters(s string) string {
	for range maxParamNesting {
		next := replaceUnescaped(s, bracedParamRe, func(m []string) (string, bool) {
			if m[3] == "IFS" {
				return "", false
			}
			return unsetBracedValue(m[1] != "", m[4]), true
		})
		if next == s {
			break
		}
		s = next
	}
	return replaceUnescaped(s, bareParamRe, func(m []string) (string, bool) {
		if m[1] == "IFS" {
			return "", false
		}
		return "", true
	})
}

// unsetBracedValue is the value of ${name rest} (or ${#name rest} when
// length is set) for an unset name. Bash's substring form ${x: -1} needs a
// space or parenthesis after the colon, so ":-" is always the default-value
// operator.
func unsetBracedValue(length bool, rest string) string {
	if length {
		if rest == "" {
			return "0"
		}
		return ""
	}
	for _, op := range []string{":-", ":=", "-", "="} {
		if word, ok := strings.CutPrefix(rest, op); ok {
			return word
		}
	}
	return ""
}

// replaceUnescaped replaces each match of re in s for which repl returns
// true, keeping matches whose dollar sign is escaped with a backslash.
func replaceUnescaped(s string, re *regexp.Regexp, repl func(m []string) (string, bool)) string {
	locs := re.FindAllStringSubmatchIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if start > 0 && s[start-1] == '\\' {
			continue
		}
		m := make([]string, len(loc)/2)
		for i := range m {
			if loc[2*i] >= 0 {
				m[i] = s[loc[2*i]:loc[2*i+1]]
			}
		}
		value, ok := repl(m)
		if !ok {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(value)
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

// shellWordBreaks end a word for brace and bracket expansion: blanks and the
// shell's control and redirection operators.
const shellWordBreaks = " \t\n\r;|&<>()"

// expandWords applies brace and bracket expansion to each word of s.
func expandWords(s string) string {
	var b strings.Builder
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		b.WriteString(expandWord(s[start:end]))
		start = -1
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(shellWordBreaks, s[i]) >= 0 {
			flush(i)
			b.WriteByte(s[i])
			continue
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(s))
	return b.String()
}

// expandWord returns the space-separated words one word expands to, or the
// word unchanged when it has no expansion or would exceed maxWordExpansions.
func expandWord(word string) string {
	if !strings.ContainsAny(word, "{[") {
		return word
	}
	words := []string{word}
	for _, re := range []*regexp.Regexp{braceExpansionRe, bracketRe} {
		var next []string
		for _, w := range words {
			expanded, ok := expandMatches(w, re, len(next))
			if !ok {
				return word
			}
			next = append(next, expanded...)
		}
		words = next
	}
	return strings.Join(words, " ")
}

// expandMatches expands every match of re in word, left to right. Brace items
// are separated by commas; a bracket expression yields each listed character.
// have is the number of words already produced; ok is false when the total
// would exceed maxWordExpansions.
func expandMatches(word string, re *regexp.Regexp, have int) ([]string, bool) {
	loc := re.FindStringSubmatchIndex(word)
	if loc == nil {
		return []string{word}, have < maxWordExpansions
	}
	pre, inner, post := word[:loc[0]], word[loc[2]:loc[3]], word[loc[1]:]
	var items []string
	if re == bracketRe {
		items = strings.Split(inner, "")
	} else {
		items = strings.Split(inner, ",")
	}
	// The postscript may hold further expansions; each item's word carries it.
	tails, ok := expandMatches(post, re, have)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items)*len(tails))
	for _, item := range items {
		for _, tail := range tails {
			if have+len(out) >= maxWordExpansions {
				return nil, false
			}
			out = append(out, pre+item+tail)
		}
	}
	return out, true
}
