// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"path"
	"regexp"
	"strings"
)

var xargsBoundaries = strings.NewReplacer("|", " | ", ";", " ; ", "&", " & ", "(", " ( ", ")", " ) ", "{", " { ", "}", " } ")

// unresolvedXargs checks candidate utilities after xargs. Unknown options and
// wrappers retain uncertainty rather than guessing where their arguments end.
// GNU findutils, "Unsafe File Name Handling" and "Safe File Name Handling",
// specify that default xargs splits blanks/newlines and interprets quotes;
// --null instead preserves each NUL-delimited item as one argument.
func unresolvedXargs(pat *regexp.Regexp, tokens []string) bool {
	words, over := leadingWordsBounded(pat)
	if len(words) == 0 && !over {
		return false
	}
	after := false
	for _, token := range tokens {
		for _, t := range strings.Fields(xargsBoundaries.Replace(token)) {
			w := handOffWord(t)
			if after && (over || isCommandWord(w, words)) {
				return true
			}
			if path.Base(w) == "xargs" {
				after = true
			}
			if strings.ContainsAny(t, ";|&") {
				after = false
			}
		}
	}
	return false
}

// knownXargsInput proves a direct literal echo pipeline or a find pipeline
// with an explicit NUL action and delimiter. It intentionally does not emulate a shell or all find/xargs
// options. Unsupported syntax cannot grant the exemption.
// The accepted predicates are the unary tests documented by GNU findutils;
// consuming their argument is essential: -name '-print0' is not an action.
func knownXargsInput(args []string) string {
	if len(args) != 1 {
		return ""
	}
	words, ok := literalPipelineWords(args[0])
	if !ok || len(words) < 4 {
		return ""
	}
	pipe := -1
	for i, w := range words {
		if w == "|" {
			if pipe != -1 {
				return ""
			}
			pipe = i
		}
	}
	if pipe < 1 || pipe+2 >= len(words) {
		return ""
	}
	consumer := words[pipe+1:]
	if consumer[0] != "xargs" && consumer[0] != "/bin/xargs" && consumer[0] != "/usr/bin/xargs" {
		return ""
	}
	// Literal echo output is already represented by the existing word
	// matching. No file contents or directory entries can supply more words.
	// Restrict this to default xargs with no replacement or delimiter options.
	if words[0] == "echo" && !strings.HasPrefix(consumer[1], "-") {
		return consumer[1]
	}
	if !isFindCommand(words[0]) || len(consumer) < 3 {
		return ""
	}
	if consumer[1] != "-0" && consumer[1] != "--null" {
		return ""
	}
	// Only one xargs option is admitted; all remaining words belong to a
	// direct utility. Only rules for that utility can use the exemption.
	if strings.HasPrefix(consumer[2], "-") || consumer[2] == "" {
		return ""
	}
	i := 1
	for i < pipe && (words[i] == "-H" || words[i] == "-L" || words[i] == "-P") {
		i++
	}
	for i < pipe && !strings.HasPrefix(words[i], "-") {
		w := words[i]
		if w != "." && !strings.HasPrefix(w, "./") && !strings.HasPrefix(w, "/") {
			return ""
		}
		i++
	}
	printed := false
	for i < pipe {
		switch words[i] {
		case "-print0":
			if printed {
				return ""
			}
			printed = true
			i++
		case "-type", "-name", "-iname", "-path", "-ipath", "-wholename", "-perm":
			if i+1 >= pipe {
				return ""
			}
			i += 2
		default:
			return ""
		}
	}
	if printed {
		return consumer[2]
	}
	return ""
}

// literalPipelineWords recognizes literal shell words and a single pipe. Shell
// expansion, redirects, control operators and escapes require a fuller analysis
// and are rejected. POSIX shell quoting makes quoted blanks part of one word.
func literalPipelineWords(s string) ([]string, bool) {
	var words []string
	var word strings.Builder
	var quote byte
	started := false
	flush := func() {
		if started {
			words = append(words, word.String())
			word.Reset()
			started = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Reject expansions even in quotes. This is deliberately narrower
		// than shell syntax; rejecting cannot clear an incomplete check.
		if strings.ContainsRune("$`\\\n\r\x00", rune(c)) {
			return nil, false
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote, started = c, true
		case ' ', '\t':
			flush()
		case '|':
			flush()
			words = append(words, "|")
		case ';', '&', '<', '>', '(', ')', '{', '}', '*', '?', '[', ']', '~', '#':
			return nil, false
		default:
			started = true
			word.WriteByte(c)
		}
	}
	flush()
	return words, quote == 0
}
