// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Admission uses the existing 4096-byte reference and 13.562 decoded bytes
// per raw byte across RFC 4648 phases. This is a uniform-junk model, not a
// probability guarantee about natural language or adversarial input.
const assembledJunkExposure = 13.562 * maxReassembledTokenLen

// Compute the syntax tree's minimum-match model weight. Concatenation
// multiplies and alternatives sum, including overlapping derivations;
// repetitions contribute their minimum required match. Optional parts and
// empty assertions contribute one: boundaries never improve admission.
// Syntax and case folding follow Go regexp/syntax and unicode.SimpleFold.
func assembledJunkWeight(r *syntax.Regexp) float64 {
	switch r.Op {
	case syntax.OpNoMatch:
		return 0
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 1
	case syntax.OpLiteral:
		p := 1.0
		for _, c := range r.Rune {
			w := assembledJunkRune(c)
			if r.Flags&syntax.FoldCase != 0 {
				for f := unicode.SimpleFold(c); f != c; f = unicode.SimpleFold(f) {
					w += assembledJunkRune(f)
				}
			}
			p *= w
		}
		return p
	case syntax.OpCharClass:
		p := 0.0
		for i := 0; i < len(r.Rune); i += 2 {
			lo, hi := r.Rune[i], r.Rune[i+1]
			for _, width := range []struct {
				lo, hi rune
				n      int
			}{{0, 0x7f, 1}, {0x80, 0x7ff, 2}, {0x800, 0xd7ff, 3}, {0xe000, 0xffff, 3}, {0x10000, utf8.MaxRune, 4}} {
				count := min(hi, width.hi) - max(lo, width.lo) + 1
				if count > 0 {
					p += float64(count) * math.Pow(1.0/256, float64(width.n))
				}
			}
			if lo <= utf8.RuneError && hi >= utf8.RuneError {
				p += assembledInvalidRuneWeight
			}
		}
		return p
	case syntax.OpAnyChar:
		return 1
	case syntax.OpAnyCharNotNL:
		return 255.0 / 256
	case syntax.OpCapture:
		return assembledJunkWeight(r.Sub[0])
	case syntax.OpConcat:
		p := 1.0
		for _, sub := range r.Sub {
			p *= assembledJunkWeight(sub)
		}
		return p
	case syntax.OpAlternate:
		p := 0.0
		for _, sub := range r.Sub {
			p += assembledJunkWeight(sub)
		}
		return p
	case syntax.OpQuest, syntax.OpStar:
		return 1
	case syntax.OpPlus:
		return assembledJunkWeight(r.Sub[0])
	case syntax.OpRepeat:
		return math.Pow(assembledJunkWeight(r.Sub[0]), float64(r.Min))
	default:
		return math.Inf(1)
	}
}

// RFC 3629 sections 3-4 give the valid scalar ranges and UTF-8 lengths.
// Go regexp decodes invalid UTF-8 as one RuneError per invalid byte. Under
// uniform independent input bytes, the remaining leading-byte mass is invalid.
const assembledInvalidRuneWeight = 1 - (128.0/256 + 1920.0/(256*256) + 61440.0/(256*256*256) + 1048576.0/(256*256*256*256))

func assembledJunkRune(r rune) float64 {
	if r == utf8.RuneError {
		return assembledInvalidRuneWeight + 1.0/(256*256*256)
	}
	n := utf8.RuneLen(r)
	if n < 0 {
		return 1
	}
	return math.Pow(1.0/256, float64(n))
}

// Only whole top-level alternatives can be removed without changing a sibling's
// language. Factored alternatives inside concatenations stay a single unit.
func assembledAdmittedTree(tree *syntax.Regexp) (*syntax.Regexp, bool) {
	var admitted []*syntax.Regexp
	residual := false
	for _, branch := range assembledShapeBranches(tree) {
		raw := assembledRawAdmits(branch)
		shape := reassemblyMaxBytes(branch) >= 0 && shapeMinLen(branch)*8/6-2 >= 1
		expected := assembledJunkExposure * assembledJunkWeight(branch)
		if math.IsNaN(expected) || expected > 1 || !raw && !shape {
			residual = true
			continue
		}
		admitted = append(admitted, branch)
	}

	selected := assembledAdmissionTree(admitted)
	// The inherited builder either covers every branch with its shared literal
	// set or builds finite shape screens. A raw-only unbounded sibling cannot
	// silently join a shape-only sibling through the whole confirmation regex.
	if selected != nil && !assembledRawAdmits(selected) {
		finite := admitted[:0]
		for _, branch := range admitted {
			if reassemblyMaxBytes(branch) >= 0 && shapeMinLen(branch)*8/6-2 >= 1 {
				finite = append(finite, branch)
			} else {
				residual = true
			}
		}
		selected = assembledAdmissionTree(finite)
	}
	// Admission of alternatives separately must still respect the pattern's
	// summed expected-match limit; do not choose an arbitrary winning subset.
	if selected != nil && assembledJunkExposure*assembledJunkWeight(selected) > 1 {
		return nil, true
	}
	return selected, residual
}

func assembledAdmissionTree(branches []*syntax.Regexp) *syntax.Regexp {
	if len(branches) == 0 {
		return nil
	}
	if len(branches) == 1 {
		return branches[0]
	}
	return &syntax.Regexp{Op: syntax.OpAlternate, Sub: branches}
}

func assembledRawAdmits(tree *syntax.Regexp) bool {
	literals := assembledAdmissionLiterals(tree)
	rate := 0.0
	for _, literal := range literals {
		rate += 13.562 * math.Pow(1.0/128, float64(len(literal)))
	}
	return len(literals) > 0 && rate <= 1.0/maxReassembledTokenLen && !slices.ContainsFunc(literals, func(lit string) bool { return strings.ContainsRune(lit, utf8.RuneError) })
}

func assembledAdmissionLiterals(tree *syntax.Regexp) []string {
	literals := reassemblyRequired(tree)
	if leading, _ := leadingLiteralAnchors(tree); betterAnchorSet(leading, literals) {
		literals = leading
	}
	return literals
}

func assembledAdmissionRegexp(tree *syntax.Regexp) *regexp.Regexp {
	return regexp.MustCompile(tree.String())
}
