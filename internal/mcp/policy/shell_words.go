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
// time and are left as written. A word whose expansion exceeds the bounds is
// reported unreadable, and rules that do not match report an incomplete check
// (mcp_tool_policy.on_incomplete_check) instead of passing.

// maxWordExpansions bounds the words one brace or bracket expansion of a word
// may produce. It equals maxPairwiseTokens, the most tokens the pairwise
// matcher checks exhaustively. A word that would expand further keeps its
// unexpanded spelling in this view; the other views still read it.
const maxWordExpansions = maxPairwiseTokens

// maxWordExpansionSteps bounds the expansion steps for one word. Every group
// left after one-character brackets are read lists two or more items, so an
// expansion to maxWordExpansions words takes fewer than twice that many steps.
const maxWordExpansionSteps = 2 * maxWordExpansions

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
// unreadable reports a word whose expansion exceeds the bounds below; that
// word keeps its spelling, and the caller must not treat the reading as
// complete.
func readShellWords(s string) (out string, unreadable bool) {
	if strings.ContainsRune(s, '$') {
		s = readUnsetParameters(s)
	}
	if strings.ContainsAny(s, "{[") {
		s, unreadable = expandWords(s)
	}
	return s, unreadable
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

// singleBracketRe matches a bracket expression listing one literal
// character, which matches exactly that character and adds no word.
var singleBracketRe = regexp.MustCompile(`\[([A-Za-z0-9._~+@%,:=/])\]`)

// expandWords applies brace and bracket expansion to each word of s.
// unreadable reports a word whose expansion exceeded the bounds.
func expandWords(s string) (string, bool) {
	// One-character brackets are read in one linear pass, so they cannot
	// spend the expansion budget below.
	s = singleBracketRe.ReplaceAllString(s, "$1")
	var b strings.Builder
	unreadable := false
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		w, ok := expandWord(s[start:end])
		unreadable = unreadable || !ok
		b.WriteString(w)
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
	return b.String(), unreadable
}

// expandWord returns the space-separated words one word expands to. When the
// expansion exceeds the bounds it returns the word unchanged and ok false.
//
// Each step takes one pending word and expands its first brace expansion, or
// else its first bracket expression; a word with neither is finished. Nested
// braces are reached as the outer ones are consumed, as in Bash. The words are
// bounded by maxWordExpansions and the steps by maxWordExpansionSteps, so the
// work for one word is linear in its length whatever the input holds.
func expandWord(word string) (string, bool) {
	if !strings.ContainsAny(word, "{[") {
		return word, true
	}
	pending := []string{word}
	var done []string
	for steps := 0; len(pending) > 0; steps++ {
		if steps >= maxWordExpansionSteps || len(done)+len(pending) > maxWordExpansions {
			return word, false
		}
		w := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		var items []string
		loc := braceExpansionRe.FindStringSubmatchIndex(w)
		if loc != nil {
			// Count the items before building any word from them.
			if len(done)+len(pending)+strings.Count(w[loc[2]:loc[3]], ",")+1 > maxWordExpansions {
				return word, false
			}
			items = strings.Split(w[loc[2]:loc[3]], ",")
		} else if loc = bracketRe.FindStringSubmatchIndex(w); loc != nil {
			items = strings.Split(w[loc[2]:loc[3]], "")
		} else {
			done = append(done, w)
			continue
		}
		pre, post := w[:loc[0]], w[loc[1]:]
		// Push in reverse so the words come out in the shell's order.
		for i := len(items) - 1; i >= 0; i-- {
			pending = append(pending, pre+items[i]+post)
		}
	}
	return strings.Join(done, " "), true
}
