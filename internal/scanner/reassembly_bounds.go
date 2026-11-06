// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp/syntax"
	"unicode/utf8"
)

func reassemblyMaxBytes(r *syntax.Regexp) int {
	switch r.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0
	case syntax.OpLiteral:
		return utf8.UTFMax * len(r.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax
	case syntax.OpCapture:
		return reassemblyMaxBytes(r.Sub[0])
	case syntax.OpConcat:
		n := 0
		for _, s := range r.Sub {
			m := reassemblyMaxBytes(s)
			if m < 0 {
				return -1
			}
			n += m
		}
		return n
	case syntax.OpAlternate:
		n := 0
		for _, s := range r.Sub {
			m := reassemblyMaxBytes(s)
			if m < 0 {
				return -1
			}
			n = max(n, m)
		}
		return n
	case syntax.OpQuest:
		return reassemblyMaxBytes(r.Sub[0])
	case syntax.OpRepeat:
		n := reassemblyMaxBytes(r.Sub[0])
		if r.Max < 0 || n < 0 {
			return -1
		}
		return n * r.Max
	default:
		return -1
	}
}
