// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
)

// Reuse the required-anchor and leading-prefix rules from prefilter.go at
// mandatory subexpressions too. A factored keyword such as api(key|_key)
// contributes complete starts instead of only its common three-byte fragment.
// This selects cues only; assembledRawAdmits still owns pattern-class policy.
func reassemblyCueAnchors(tree *syntax.Regexp) []string {
	out := reassemblyRequired(tree)
	switch tree.Op {
	case syntax.OpCapture, syntax.OpPlus:
		out = reassemblyCueAnchors(tree.Sub[0])
	case syntax.OpRepeat:
		if tree.Min > 0 {
			out = reassemblyCueAnchors(tree.Sub[0])
		}
	case syntax.OpConcat:
		for _, sub := range tree.Sub {
			if candidate := reassemblyCueAnchors(sub); betterAnchorSet(candidate, out) {
				out = candidate
			}
		}
	case syntax.OpAlternate:
		var combined []string
		for _, sub := range tree.Sub {
			candidate := reassemblyCueAnchors(sub)
			if len(candidate) == 0 {
				return nil
			}
			combined = append(combined, candidate...)
		}
		out = combined
	}
	if leading, _ := leadingLiteralAnchors(tree); betterAnchorSet(leading, out) {
		out = leading
	}
	return out
}

// A required leading literal can verify a longer mandatory prefix before it
// admits a lane. The exposure and weight are the same admission arithmetic as
// assembledAdmittedTree; maxReassembledTokenLen bounds this local verification
// by the existing normalizer unit. Unsupported cases keep literal verification.
func assembledPrefixVerifier(tree *syntax.Regexp, literals []string) (*regexp.Regexp, int) {
	if !assembledLeadingCues(tree, literals) {
		return nil, 0
	}
	return assembledContinuationVerifier(tree)
}

// assembledCueVerifier applies the prefix verifier where the cue set starts
// a mandatory part of every match. anchors is the tree that produced the cue
// set; a case-folded tree can expand a leading class beyond literal anchors.
// Every top-level concatenation element is mandatory, so when its leading
// literals are the cue set, every match has a cue that starts that element and
// the remaining concatenation. Other shapes keep literal verification.
func assembledCueVerifier(tree, anchors *syntax.Regexp, literals []string) (*regexp.Regexp, int) {
	if assembledLeadingCues(anchors, literals) {
		if verify, size := assembledContinuationVerifier(tree); verify != nil {
			return verify, size
		}
	}
	body := tree
	for body.Op == syntax.OpCapture && len(body.Sub) == 1 {
		body = body.Sub[0]
	}
	if body.Op != syntax.OpConcat {
		return nil, 0
	}
	for i := 1; i < len(body.Sub); i++ {
		rest := &syntax.Regexp{Op: syntax.OpConcat, Flags: body.Flags, Sub: body.Sub[i:]}
		if !assembledLeadingCues(rest, literals) {
			continue
		}
		if verify, size := assembledContinuationVerifier(rest); verify != nil {
			return verify, size
		}
	}
	return nil, 0
}

// assembledLeadingCues reports whether every match of tree starts with one of
// literals, so each match has a cue at its first byte. A cue that starts no
// match only reaches a verifier that rejects it. leadingLiteralAnchors drops
// the empty start of a language that can match nothing; require a consuming
// match instead.
func assembledLeadingCues(tree *syntax.Regexp, literals []string) bool {
	leading, _ := leadingLiteralAnchors(tree)
	if len(leading) == 0 || len(literals) == 0 || shapeMinLen(tree) == 0 {
		return false
	}
	for _, start := range leading {
		if !slices.ContainsFunc(literals, func(literal string) bool { return assembledFoldPrefix(start, literal) }) {
			return false
		}
	}
	return true
}

func assembledFoldPrefix(value, prefix string) bool {
	runes, want := []rune(value), []rune(prefix)
	return len(want) > 0 && len(runes) >= len(want) && strings.EqualFold(string(runes[:len(want)]), prefix)
}

func assembledContinuationVerifier(tree *syntax.Regexp) (*regexp.Regexp, int) {
	prefix, _ := assembledMandatoryPrefix(tree)
	size := reassemblyMaxBytes(prefix)
	if size <= 0 || size > maxReassembledTokenLen || assembledJunkExposure*assembledJunkWeight(prefix) > 1 {
		return nil, 0
	}
	return regexp.MustCompile("^(?:" + prefix.String() + ")"), size
}

// The returned language contains a prefix of every match. complete means the
// entire consuming language is retained, so concatenation may continue. An
// unbounded repetition ends the fixed prefix at its minimum, as does an
// optional element whose own language is not complete; later elements have
// unknown positions. A complete optional element is present or absent. Assertions are omitted because this local
// view does not have the lane's true boundaries. Only full-lane matching checks
// assertions and accepts findings.
func assembledMandatoryPrefix(tree *syntax.Regexp) (*syntax.Regexp, bool) {
	empty := func() *syntax.Regexp { return &syntax.Regexp{Op: syntax.OpEmptyMatch} }
	switch tree.Op {
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpEmptyMatch:
		return empty(), true
	case syntax.OpCapture:
		return assembledMandatoryPrefix(tree.Sub[0])
	case syntax.OpConcat, syntax.OpAlternate:
		out := &syntax.Regexp{Op: tree.Op, Flags: tree.Flags}
		complete := true
		for _, sub := range tree.Sub {
			prefix, full := assembledMandatoryPrefix(sub)
			out.Sub = append(out.Sub, prefix)
			complete = complete && full
			if !full && tree.Op == syntax.OpConcat {
				break
			}
		}
		return out.Simplify(), complete
	case syntax.OpQuest:
		// A bounded optional element is either wholly present or absent.
		prefix, full := assembledMandatoryPrefix(tree.Sub[0])
		if !full {
			return empty(), false
		}
		return &syntax.Regexp{Op: syntax.OpAlternate, Flags: tree.Flags, Sub: []*syntax.Regexp{prefix, empty()}}, true
	case syntax.OpStar:
		return empty(), false
	case syntax.OpPlus, syntax.OpRepeat:
		minimum := tree.Min
		if tree.Op == syntax.OpPlus {
			minimum = 1
		}
		if minimum == 0 {
			return empty(), false
		}
		prefix, full := assembledMandatoryPrefix(tree.Sub[0])
		if !full {
			return prefix, false
		}
		out := &syntax.Regexp{Op: syntax.OpRepeat, Flags: tree.Flags, Min: minimum, Max: minimum, Sub: []*syntax.Regexp{prefix}}
		return out.Simplify(), tree.Op == syntax.OpRepeat && tree.Min == tree.Max
	default:
		return tree, true
	}
}
