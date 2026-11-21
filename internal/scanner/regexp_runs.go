// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	regexpWindowMinText     = 1024
	regexpWindowMaxRanges   = 256
	regexpWindowMaxAnchors  = 8
	regexpWindowAnchorBytes = 12
	regexpWindowWildRepeat  = 4
	regexpWindowMaxBlocks   = 1024
)

// regexpWindowPlan is immutable and belongs to the exact regexp it describes.
// It overestimates what a match can consume: any run of core bytes, at most
// blocks non-core runs, and at most wild non-hop bytes in those runs. All
// non-ASCII bytes are core, so artificial edges never split UTF-8.
type regexpWindowPlan struct {
	re                     *regexp.Regexp
	core, hop, first, last asciiByteSet
	blocks, wild, minimum  int
	anchors                []string
}

func newRegexpWindowPlan(re *regexp.Regexp, tree *syntax.Regexp) *regexpWindowPlan {
	minimum := shapeMinLen(tree)
	if minimum == 0 {
		// FindAll's empty-match suppression depends on the preceding match.
		return nil
	}
	w := &regexpWindowPlan{re: re, minimum: minimum}
	var leaves []regexpWindowLeaf
	if !collectRegexpWindowLeaves(tree, 1, &leaves) {
		return nil
	}
	for _, leaf := range leaves {
		if leaf.core {
			w.core.union(leaf.bytes)
		}
	}
	for _, leaf := range leaves {
		if leaf.hop && (leaf.bytes[0]&w.core[0] != 0 || leaf.bytes[1]&w.core[1] != 0) {
			// A hop split by core whitespace can visit arbitrarily many
			// non-core runs. Widen core to keep each remaining hop disjoint.
			w.core.union(regexpWhitespaceBytes)
			break
		}
	}
	if w.core == (asciiByteSet{^uint64(0), ^uint64(0)}) {
		// There is no byte that can separate two core runs.
		return nil
	}
	for _, leaf := range leaves {
		if leaf.core || leaf.bytes.subsetOf(w.core) {
			continue
		}
		if leaf.count > regexpWindowMaxBlocks-w.blocks {
			return nil
		}
		w.blocks += leaf.count
		if leaf.hop {
			w.hop.union(leaf.bytes)
		} else {
			w.wild += leaf.count
		}
	}
	if w.blocks > 0 {
		// Choose only actual literal runs. Leading anchors may contain
		// enumerated class bytes, which need not be inside one core run.
		anchors := requiredLiteralAnchors(tree)
		if len(anchors) == 0 || len(anchors) > regexpWindowMaxAnchors {
			return nil
		}
		for _, literal := range anchors {
			if !isASCIIString(literal) || len(literal) < minPreFilterAnchorLength {
				return nil
			}
			anchor := strings.ToLower(literal[:min(len(literal), regexpWindowAnchorBytes)])
			if !slices.Contains(w.anchors, anchor) {
				w.anchors = append(w.anchors, anchor)
			}
		}
		// Go regexp's Unicode simple-fold orbits for ASCII letters contain
		// two non-ASCII members. Where relevant, a window around either rune
		// is also a candidate, even when the full ASCII anchor is absent.
		for _, anchor := range w.anchors {
			if strings.ContainsRune(anchor, 'k') && !slices.Contains(w.anchors, "K") {
				w.anchors = append(w.anchors, "K")
			}
			if strings.ContainsRune(anchor, 's') && !slices.Contains(w.anchors, "ſ") {
				w.anchors = append(w.anchors, "ſ")
			}
		}
	}
	w.first, _ = regexpEdgeBytes(tree, false)
	w.last, _ = regexpEdgeBytes(tree, true)
	return w
}

type regexpWindowLeaf struct {
	bytes     asciiByteSet
	count     int
	core, hop bool
}

// Each repetition of a whitespace-only class consumes at most one non-core
// block. A small finite repetition of another class can spend one wild byte
// and one block per rune. Everything else contributes to the core alphabet.
func collectRegexpWindowLeaves(tree *syntax.Regexp, repeats int, leaves *[]regexpWindowLeaf) bool {
	switch tree.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
	case syntax.OpLiteral:
		var bytes asciiByteSet
		for _, r := range tree.Rune {
			addRegexpLiteralBytes(&bytes, r, tree.Flags&syntax.FoldCase != 0)
		}
		*leaves = append(*leaves, regexpWindowLeaf{bytes: bytes, core: true})
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		*leaves = append(*leaves, regexpWindowLeaf{
			bytes: regexpClassBytes(tree), count: repeats,
			core: repeats < 0 || repeats > regexpWindowWildRepeat,
		})
	case syntax.OpCapture, syntax.OpConcat, syntax.OpAlternate, syntax.OpQuest:
		for _, sub := range tree.Sub {
			if !collectRegexpWindowLeaves(sub, repeats, leaves) {
				return false
			}
		}
	case syntax.OpRepeat, syntax.OpStar, syntax.OpPlus:
		limit := -1
		if tree.Op == syntax.OpRepeat {
			limit = tree.Max
		}
		sub := tree.Sub[0]
		if limit < 0 && repeats >= 0 {
			for sub.Op == syntax.OpCapture {
				sub = sub.Sub[0]
			}
			if sub.Op == syntax.OpCharClass && regexpASCIIWhitespace(sub) {
				*leaves = append(*leaves, regexpWindowLeaf{bytes: regexpClassBytes(sub), count: repeats, hop: true})
				return true
			}
		}
		// A larger enclosing count promotes both classes and whitespace
		// repeats to core, avoiding an underestimated block count.
		if repeats < 0 || limit < 0 || limit > 0 && repeats > regexpWindowMaxBlocks/limit {
			repeats = -1
		} else {
			repeats *= limit
		}
		return collectRegexpWindowLeaves(sub, repeats, leaves)
	default:
		return false
	}
	return true
}

func addRegexpLiteralBytes(set *asciiByteSet, r rune, fold bool) {
	if r < utf8.RuneSelf {
		set.addRune(r)
	}
	if fold {
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < utf8.RuneSelf {
				set.addRune(next)
			}
		}
	}
}

func regexpClassBytes(tree *syntax.Regexp) (set asciiByteSet) {
	switch tree.Op {
	case syntax.OpAnyChar:
		return asciiByteSet{^uint64(0), ^uint64(0)}
	case syntax.OpAnyCharNotNL:
		return asciiByteSet{^uint64(1 << '\n'), ^uint64(0)}
	case syntax.OpCharClass:
		for i := 0; i+1 < len(tree.Rune); i += 2 {
			for r := tree.Rune[i]; r <= tree.Rune[i+1] && r < utf8.RuneSelf; r++ {
				set.addRune(r)
			}
		}
	}
	return set
}

func regexpASCIIWhitespace(tree *syntax.Regexp) bool {
	return len(tree.Rune) > 0 && tree.Rune[len(tree.Rune)-1] < utf8.RuneSelf &&
		regexpClassBytes(tree).subsetOf(regexpWhitespaceBytes)
}

var regexpWhitespaceBytes = func() (set asciiByteSet) {
	for _, r := range " \t\n\r\f\v" {
		set.addRune(r)
	}
	return set
}()

// regexpEdgeBytes returns the ASCII bytes a match of tree can begin with, or
// end with when fromEnd is set, and whether tree can match the empty string.
// Unknown syntax yields every byte, which only widens a slice.
func regexpEdgeBytes(tree *syntax.Regexp, fromEnd bool) (set asciiByteSet, nullable bool) {
	switch tree.Op {
	case syntax.OpNoMatch:
		return set, false
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return set, true
	case syntax.OpLiteral:
		if len(tree.Rune) == 0 {
			return set, true
		}
		r := tree.Rune[0]
		if fromEnd {
			r = tree.Rune[len(tree.Rune)-1]
		}
		addRegexpLiteralBytes(&set, r, tree.Flags&syntax.FoldCase != 0)
		return set, false
	case syntax.OpCharClass, syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return regexpClassBytes(tree), false
	case syntax.OpCapture, syntax.OpPlus:
		return regexpEdgeBytes(tree.Sub[0], fromEnd)
	case syntax.OpStar, syntax.OpQuest:
		set, _ = regexpEdgeBytes(tree.Sub[0], fromEnd)
		return set, true
	case syntax.OpRepeat:
		set, nullable = regexpEdgeBytes(tree.Sub[0], fromEnd)
		return set, nullable || tree.Min == 0
	case syntax.OpAlternate:
		for _, sub := range tree.Sub {
			subSet, subNullable := regexpEdgeBytes(sub, fromEnd)
			set.union(subSet)
			nullable = nullable || subNullable
		}
		return set, nullable
	case syntax.OpConcat:
		nullable = true
		for i := range tree.Sub {
			sub := tree.Sub[i]
			if fromEnd {
				sub = tree.Sub[len(tree.Sub)-1-i]
			}
			subSet, subNullable := regexpEdgeBytes(sub, fromEnd)
			set.union(subSet)
			if !subNullable {
				return set, false
			}
		}
		return set, nullable
	default:
		return asciiByteSet{^uint64(0), ^uint64(0)}, true
	}
}

func regexpWindowHas(set asciiByteSet, b byte) bool {
	return b >= utf8.RuneSelf || set.has(b)
}

// grow starts inside a mandatory literal (or a core run when all consumed
// bytes are core). In each direction it spends the entire match allowance,
// which encloses every match touching the run. It returns the first core
// run's edge separately so later anchors in that run need no new growth.
func (w *regexpWindowPlan) grow(text string, at, step int, budget *int) (edge, coreEdge int) {
	coreEdge = -1
	blocks, wild := w.blocks, w.wild
	inBlock := false
	shift := min(step, 0)
	for i := at + shift; i >= 0 && i < len(text) && *budget > 0; i += step {
		b := text[i]
		if regexpWindowHas(w.core, b) {
			inBlock = false
		} else {
			if coreEdge < 0 {
				coreEdge = at
			}
			if !inBlock {
				if blocks == 0 {
					break
				}
				blocks--
				inBlock = true
			}
			if !w.hop.has(b) {
				if wild == 0 {
					break
				}
				wild--
			}
		}
		*budget--
		at += step
	}
	if coreEdge < 0 {
		coreEdge = at
	}
	return at, coreEdge
}

// pad keeps any match away from an artificial edge. A guard byte that
// cannot begin (end) a match gives Go regexp the real context to its right
// (left), including newline and ASCII word boundaries. At the real input
// edge no guard is needed.
func padRegexpWindow(text string, at, step int, edges asciiByteSet, budget *int) int {
	shift := min(step, 0)
	for i := at + shift; i >= 0 && i < len(text) && *budget > 0; i += step {
		*budget--
		at += step
		if !regexpWindowHas(edges, text[i]) {
			break
		}
	}
	return at
}

type regexpWindowRange struct{ start, end int }

// ranges returns disjoint ordered slices containing every possible match.
// Overlapping slices merge before evaluation so a competing match or a
// non-overlap decision can never be lost at a seam. The bounded plan is
// discarded as a unit on fallback, before any regexp or validator runs.
func (w *regexpWindowPlan) ranges(text string) ([]regexpWindowRange, bool) {
	var finders [regexpWindowMaxAnchors + 2]windowLiteralFinder
	for i, anchor := range w.anchors {
		finders[i] = newWindowLiteralFinder(anchor)
	}
	var windows []regexpWindowRange
	budget := len(text)
	for from := 0; from < len(text); {
		var at int
		if len(w.anchors) == 0 {
			at = from
			for at < len(text) && !regexpWindowHas(w.core, text[at]) {
				at++
			}
		} else {
			at = len(text)
			for i := range w.anchors {
				at = min(at, finders[i].next(text, from))
			}
		}
		if at == len(text) {
			break
		}
		start, _ := w.grow(text, at, -1, &budget)
		end, coreEnd := w.grow(text, at, 1, &budget)
		from = coreEnd
		if budget == 0 || from <= at {
			return nil, false
		}
		if end-start < w.minimum {
			continue
		}
		start = padRegexpWindow(text, start, -1, w.first, &budget)
		end = padRegexpWindow(text, end, 1, w.last, &budget)
		if budget == 0 || end-start == len(text) {
			return nil, false
		}
		if n := len(windows); n > 0 {
			last := &windows[n-1]
			if start < last.start {
				return nil, false
			}
			if start < last.end {
				last.end = max(last.end, end)
				continue
			}
		}
		if len(windows) == regexpWindowMaxRanges {
			return nil, false
		}
		windows = append(windows, regexpWindowRange{start, end})
	}
	return windows, true
}

func (w *regexpWindowPlan) findAll(re *regexp.Regexp, text string) [][]int {
	return w.findAllInView(re, re, text, text)
}

// The alternate matcher is admitted only by the ASCII-folded path, which
// already proves that its matches and byte offsets agree with the source RE.
func (w *regexpWindowPlan) findAllInView(source, matcher *regexp.Regexp, text, view string) [][]int {
	if w == nil || w.re != source || len(text) < regexpWindowMinText {
		return matcher.FindAllStringIndex(view, -1)
	}
	windows, ok := w.ranges(text)
	if !ok {
		return matcher.FindAllStringIndex(view, -1)
	}
	var out [][]int
	for _, window := range windows {
		for _, match := range matcher.FindAllStringIndex(view[window.start:window.end], -1) {
			match[0] += window.start
			match[1] += window.start
			out = append(out, match)
		}
	}
	return out
}

// windowLiteralFinder searches an ASCII-lowercase literal with ASCII case
// ignored, or one exact UTF-8 fold member. Its two first-byte cursors never
// rewind when another anchor wins the current candidate. Needle length and
// the number of finders are capped independently of the expression size.
type windowLiteralFinder struct {
	needle               string
	lower, upper         byte
	nextLower, nextUpper int
}

func newWindowLiteralFinder(needle string) windowLiteralFinder {
	lower := needle[0]
	upper := lower
	if lower >= 'a' && lower <= 'z' {
		upper = lower - ('a' - 'A')
	}
	return windowLiteralFinder{needle: needle, lower: lower, upper: upper, nextLower: -1, nextUpper: -1}
}

func (f *windowLiteralFinder) next(text string, from int) int {
	for {
		if f.nextLower < from {
			f.nextLower = windowIndexByte(text, f.lower, from)
		}
		if f.nextUpper < from {
			f.nextUpper = len(text)
			if f.upper != f.lower {
				f.nextUpper = windowIndexByte(text, f.upper, from)
			}
		}
		at := min(f.nextLower, f.nextUpper)
		if at > len(text)-len(f.needle) {
			return len(text)
		}
		if windowLiteralEqual(text[at:], f.needle) {
			return at
		}
		from = at + 1
	}
}

func windowIndexByte(text string, b byte, from int) int {
	if i := strings.IndexByte(text[from:], b); i >= 0 {
		return from + i
	}
	return len(text)
}

func windowLiteralEqual(text, needle string) bool {
	for i := 0; i < len(needle); i++ {
		if asciiLower(text[i]) != needle[i] {
			return false
		}
	}
	return true
}
