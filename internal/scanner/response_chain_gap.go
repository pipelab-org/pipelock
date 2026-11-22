// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp/syntax"
	"unicode"
	"unicode/utf8"
)

type responseChainGapClass struct {
	ascii asciiByteSet
	high  bool
}

// A gap with pairwise disjoint byte classes can consume at most one run of
// each in order. Dropping run minimums and maximums gives a necessary upper
// bound without backtracking. High bytes are allowed together whenever a
// class admits any non-ASCII rune.
type responseChainGapShape struct {
	classes [3]responseChainGapClass
	count   int
	opaque  bool
}

func responseChainGapShapeFor(tree *syntax.Regexp) responseChainGapShape {
	switch tree.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return responseChainGapShape{}
	case syntax.OpCapture, syntax.OpRepeat, syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		shape := responseChainGapShapeFor(tree.Sub[0])
		if tree.Op == syntax.OpCapture || tree.Op == syntax.OpQuest || shape.count <= 1 {
			return shape
		}
	case syntax.OpConcat:
		var shape responseChainGapShape
		for _, sub := range tree.Sub {
			shape = shape.plus(responseChainGapShapeFor(sub))
		}
		return shape
	case syntax.OpCharClass:
		return singleResponseChainGapClass(responseChainGapClass{
			ascii: regexpClassBytes(tree),
			high:  len(tree.Rune) > 0 && tree.Rune[len(tree.Rune)-1] >= utf8.RuneSelf,
		})
	case syntax.OpLiteral:
		if len(tree.Rune) == 1 {
			r := tree.Rune[0]
			fold := tree.Flags&syntax.FoldCase != 0
			class := responseChainGapClass{high: r >= utf8.RuneSelf}
			addRegexpLiteralBytes(&class.ascii, r, fold)
			if fold {
				for alt := unicode.SimpleFold(r); alt != r; alt = unicode.SimpleFold(alt) {
					class.high = class.high || alt >= utf8.RuneSelf
				}
			}
			return singleResponseChainGapClass(class)
		}
	}
	return responseChainGapShape{opaque: true}
}

func singleResponseChainGapClass(class responseChainGapClass) responseChainGapShape {
	return responseChainGapShape{classes: [3]responseChainGapClass{class}, count: 1}
}

func (s responseChainGapShape) plus(t responseChainGapShape) responseChainGapShape {
	if s.opaque || t.opaque {
		return responseChainGapShape{opaque: true}
	}
	for _, class := range t.classes[:t.count] {
		if s.count > 0 && class == s.classes[s.count-1] {
			continue
		}
		if s.count == len(s.classes) {
			return responseChainGapShape{opaque: true}
		}
		for _, prior := range s.classes[:s.count] {
			if prior.high && class.high || prior.ascii[0]&class.ascii[0] != 0 || prior.ascii[1]&class.ascii[1] != 0 {
				return responseChainGapShape{opaque: true}
			}
		}
		s.classes[s.count] = class
		s.count++
	}
	return s
}

func (s responseChainGapShape) end(text string, start, upper int) int {
	at := start
	limit := min(upper, start+responseChainLocalGapLimit)
	for _, class := range s.classes[:s.count] {
		for at < limit {
			b := text[at]
			if b >= utf8.RuneSelf && !class.high || b < utf8.RuneSelf && !class.ascii.has(b) {
				break
			}
			at++
		}
	}
	if at < limit {
		return at
	}
	return upper
}
