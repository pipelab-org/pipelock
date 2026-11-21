// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
)

// compileASCIIFoldedRegexp builds the same matching language for a view whose
// ASCII uppercase bytes become lowercase. All other bytes, including invalid
// UTF-8, stay unchanged, so match and capture offsets index the original view.
// Unsupported or case-sensitive grammars keep their original regexp.
func compileASCIIFoldedRegexp(source string) *regexp.Regexp {
	tree, err := syntax.Parse(source, syntax.Perl)
	if err != nil {
		return nil
	}
	changed := false
	var rewrite func(*syntax.Regexp) (*syntax.Regexp, bool)
	rewrite = func(node *syntax.Regexp) (*syntax.Regexp, bool) {
		cp := *node
		switch node.Op {
		case syntax.OpLiteral:
			var children []*syntax.Regexp
			for _, r := range node.Rune {
				flags := node.Flags
				if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
					if flags&syntax.FoldCase == 0 {
						return nil, false
					}
					runes := []rune{}
					for next := r; ; {
						lowered := next
						if lowered >= 'A' && lowered <= 'Z' {
							lowered += 'a' - 'A'
						}
						runes = append(runes, lowered)
						next = unicode.SimpleFold(next)
						if next == r {
							break
						}
					}
					slices.Sort(runes)
					runes = slices.Compact(runes)
					changed = true
					if len(runes) == 1 {
						children = append(children, &syntax.Regexp{Op: syntax.OpLiteral, Flags: flags &^ syntax.FoldCase, Rune: runes})
					} else {
						ranges := []rune{}
						for _, v := range runes {
							ranges = append(ranges, v, v)
						}
						children = append(children, &syntax.Regexp{Op: syntax.OpCharClass, Flags: flags &^ syntax.FoldCase, Rune: ranges})
					}
					continue
				}
				children = append(children, &syntax.Regexp{Op: syntax.OpLiteral, Flags: flags, Rune: []rune{r}})
			}
			if len(children) == 1 {
				return children[0], true
			}
			return &syntax.Regexp{Op: syntax.OpConcat, Sub: children}, true
		case syntax.OpCharClass:
			has := func(r rune) bool {
				for i := 0; i < len(node.Rune); i += 2 {
					if r >= node.Rune[i] && r <= node.Rune[i+1] {
						return true
					}
				}
				return false
			}
			for r := 'A'; r <= 'Z'; r++ {
				if has(r) != has(r+'a'-'A') {
					return nil, false
				}
			}
			cp.Rune = nil
			for i := 0; i < len(node.Rune); i += 2 {
				lo, hi := node.Rune[i], node.Rune[i+1]
				if hi < 'A' || lo > 'Z' {
					cp.Rune = append(cp.Rune, lo, hi)
					continue
				}
				if lo < 'A' {
					cp.Rune = append(cp.Rune, lo, 'A'-1)
				}
				if hi > 'Z' {
					cp.Rune = append(cp.Rune, 'Z'+1, hi)
				}
			}
			cp.Flags &^= syntax.FoldCase

		case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpAnyCharNotNL, syntax.OpAnyChar, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat, syntax.OpConcat, syntax.OpAlternate:
			cp.Sub = make([]*syntax.Regexp, len(node.Sub))
			for i, ch := range node.Sub {
				var ok bool
				cp.Sub[i], ok = rewrite(ch)
				if !ok {
					return nil, false
				}
			}
		default:
			return nil, false
		}
		return &cp, true
	}
	plan, ok := rewrite(tree)
	if !ok || !changed {
		return nil
	}
	alt, err := regexp.Compile(plan.String())
	if err != nil {
		return nil
	}
	return alt
}

func lowerASCIIForRegexp(s string) string {
	i := 0
	for i < len(s) && (s[i] < 'A' || s[i] > 'Z') {
		i++
	}
	if i == len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(s[:i])
	for ; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// prepareASCIIFoldedRegexp runs only while constructing immutable scanner
// patterns from compileScannerRegexp's Perl, first-match expressions.
func (p *compiledPattern) prepareASCIIFoldedRegexp() {
	if p.withoutLeftBoundary != nil || p.keywords != nil || p.wifOverlapRetry {
		return
	}
	p.asciiFoldedRE = compileASCIIFoldedRegexp(p.re.String())
	p.asciiFoldedSource = p.re
}

// asciiFoldedInput is borrowed by one synchronous pattern loop. It never
// enters a memo or a shared cache, and one input must serve only one view.
type asciiFoldedInput struct {
	text  string
	ready bool
}

func (v *asciiFoldedInput) get(source string) string {
	if !v.ready {
		v.text = lowerASCIIForRegexp(source)
		v.ready = true
	}
	return v.text
}

// matchSpanInPreparedView changes only the regexp's input and instructions.
// Admission, validators, source context and returned spans use original bytes.
func (p *compiledPattern) matchSpanInPreparedView(text, source string, input *asciiFoldedInput, memo *decodingMemo) (int, int, bool) {
	if p.asciiFoldedRE == nil || p.asciiFoldedSource != p.re || p.withoutLeftBoundary != nil || p.keywords != nil || p.wifOverlapRetry {
		return p.matchSpanWithDecodes(text, source, memo)
	}
	if !p.admitsView(text) {
		return 0, 0, false
	}
	locations := p.regexpWindows.findAllInView(p.re, p.asciiFoldedRE, text, input.get(text))
	return p.firstAcceptedLocations(text, locations, nil)
}
