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
	responseWindowMaxWidth   = 32 << 10
	responseWindowMaxAnchors = 32
	responseWindowMaxRanges  = 1024
)

// responseWindowWidth bounds consumed bytes by fixed + runs*maxRun, where
// maxRun is measured on the exact input view. No whitespace is rewritten.
type responseWindowWidth struct {
	fixed, runs int
}

var responseWindowRunBytes = func() asciiByteSet {
	set := regexpWhitespaceBytes
	for _, b := range "0123456789_-" {
		set.addRune(b)
	}
	return set
}()

func responseRegexpWidth(tree *syntax.Regexp) (responseWindowWidth, bool) {
	return responseRegexpWidthWith(tree, func(sub *syntax.Regexp) (responseWindowWidth, bool) {
		for sub.Op == syntax.OpCapture {
			sub = sub.Sub[0]
		}
		if sub.Op == syntax.OpCharClass && len(sub.Rune) > 0 && sub.Rune[len(sub.Rune)-1] < utf8.RuneSelf &&
			regexpClassBytes(sub).subsetOf(responseWindowRunBytes) {
			return responseWindowWidth{runs: 1}, true
		}
		return responseWindowWidth{}, false
	})
}

func responseRegexpWidthWith(tree *syntax.Regexp, repeat func(*syntax.Regexp) (responseWindowWidth, bool)) (width responseWindowWidth, ok bool) {
	switch tree.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
	case syntax.OpLiteral:
		for _, r := range tree.Rune {
			// RuneError may also represent one invalid byte. Its encoded
			// width still bounds either representation.
			n := utf8.RuneLen(r)
			if tree.Flags&syntax.FoldCase != 0 {
				for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
					n = max(n, utf8.RuneLen(folded))
				}
			}
			width.fixed += n
		}
	case syntax.OpCharClass:
		if len(tree.Rune) > 0 {
			width.fixed = utf8.RuneLen(tree.Rune[len(tree.Rune)-1])
		}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		width.fixed = utf8.UTFMax
	case syntax.OpConcat, syntax.OpAlternate:
		for _, sub := range tree.Sub {
			w, bounded := responseRegexpWidthWith(sub, repeat)
			if !bounded {
				return responseWindowWidth{}, false
			}
			if tree.Op == syntax.OpConcat {
				width.fixed += w.fixed
				width.runs += w.runs
			} else {
				width.fixed = max(width.fixed, w.fixed)
				width.runs = max(width.runs, w.runs)
			}
		}
	case syntax.OpCapture, syntax.OpQuest:
		return responseRegexpWidthWith(tree.Sub[0], repeat)
	case syntax.OpRepeat, syntax.OpStar, syntax.OpPlus:
		sub := tree.Sub[0]
		if tree.Op != syntax.OpRepeat || tree.Max < 0 {
			return repeat(sub)
		}
		w, bounded := responseRegexpWidthWith(sub, repeat)
		if !bounded || tree.Max > 0 && (w.fixed > responseWindowMaxWidth/tree.Max || w.runs > responseWindowMaxWidth/tree.Max) {
			return responseWindowWidth{}, false
		}
		width = responseWindowWidth{fixed: w.fixed * tree.Max, runs: w.runs * tree.Max}
	default:
		return responseWindowWidth{}, false
	}
	return width, width.fixed <= responseWindowMaxWidth && width.runs <= responseWindowMaxWidth
}

func responseMaxWindowRun(text string) int {
	longest, run := 0, 0
	for i := range len(text) {
		if responseWindowRunBytes.has(text[i]) {
			run++
			continue
		}
		longest = max(longest, run)
		run = 0
	}
	return max(longest, run)
}

func newResponseRegexpWindowPlan(re *regexp.Regexp, tree *syntax.Regexp) *regexpWindowPlan {
	width, ok := responseRegexpWidth(tree)
	if !ok || shapeMinLen(tree) == 0 || regexpStartsAtTextBeginning(tree) {
		return nil
	}
	plan := &regexpWindowPlan{re: re, responseWidth: width}
	if !plan.setLiteralAnchors(tree, responseWindowMaxAnchors) {
		return nil
	}
	plan.first, _ = regexpEdgeBytes(tree, false)
	plan.last, _ = regexpEdgeBytes(tree, true)
	return plan
}

// Every match contains a candidate start. Its entire consumed span therefore
// lies within width bytes on either side. Guard bytes preserve empty-width
// assertions in Go regexp. The original regex evaluates each merged range
// once, so alternative priority and FindAll's non-overlap rule are unchanged.
func (w *regexpWindowPlan) responseRanges(text, folded string, positions *matchingView, maxRun int) ([]regexpWindowRange, bool) {
	if w.responseWidth.runs != 0 && maxRun > (responseWindowMaxWidth-w.responseWidth.fixed)/w.responseWidth.runs {
		return nil, false
	}
	width := w.responseWidth.fixed + w.responseWidth.runs*maxRun
	if width == 0 || width > responseWindowMaxWidth || width >= len(text)/2 {
		return nil, false
	}
	anchors := newRegexpWindowAnchors(w.anchors, folded, positions)
	var windows []regexpWindowRange
	budget := len(text)
	for from := 0; from < len(text); {
		at := anchors.next(text, folded, from)
		if at == len(text) {
			break
		}
		from = at + 1
		start, end := max(0, at-width), min(len(text), at+width)
		if n := len(windows); n > 0 {
			last := &windows[n-1]
			if start >= last.start && end <= last.end {
				continue
			}
		}
		start = padRegexpWindow(text, start, -1, w.first, &budget)
		end = padRegexpWindow(text, end, 1, w.last, &budget)
		if budget == 0 {
			return nil, false
		}
		if n := len(windows); n > 0 {
			last := &windows[n-1]
			if start < last.start {
				return nil, false
			}
			if start <= last.end {
				budget -= max(0, end-last.end)
				last.end = max(last.end, end)
				if budget <= 0 {
					return nil, false
				}
				continue
			}
		}
		if len(windows) == responseWindowMaxRanges {
			return nil, false
		}
		budget -= end - start
		if budget <= 0 {
			return nil, false
		}
		windows = append(windows, regexpWindowRange{start, end})
	}
	return windows, true
}

// Each cursor reuses a complete position index or searches only forward. The
// folded string is used only when simple folding preserves all byte offsets.
type regexpWindowAnchor struct {
	positions []int
	finder    windowLiteralFinder
	folded    string
	nextFold  int
}

type regexpWindowAnchors []regexpWindowAnchor

func newRegexpWindowAnchors(needles []string, folded string, view *matchingView) regexpWindowAnchors {
	anchors := make(regexpWindowAnchors, 0, len(needles))
	for _, literal := range needles {
		switch positions, indexed := view.positions(literal); {
		case indexed:
			anchors = append(anchors, regexpWindowAnchor{positions: positions})
		case folded == "":
			anchors = append(anchors, regexpWindowAnchor{finder: newWindowLiteralFinder(literal)})
		case isASCIIString(literal):
			anchors = append(anchors, regexpWindowAnchor{folded: responseSimpleFold(literal), nextFold: -1})
			// Non-ASCII anchors are simple-fold members of ASCII letters.
			// None can exist in an input whose folded offsets are unchanged.
		}
	}
	return anchors
}

func (anchors regexpWindowAnchors) next(text, folded string, from int) int {
	at := len(text)
	for i := range anchors {
		cursor := &anchors[i]
		switch {
		case cursor.folded != "":
			if cursor.nextFold < from {
				cursor.nextFold = len(text)
				if found := strings.Index(folded[from:], cursor.folded); found >= 0 {
					cursor.nextFold = from + found
				}
			}
			at = min(at, cursor.nextFold)
		case cursor.finder.needle != "":
			at = min(at, cursor.finder.next(text, from))
		default:
			for len(cursor.positions) > 0 && cursor.positions[0] < from {
				cursor.positions = cursor.positions[1:]
			}
			if len(cursor.positions) > 0 {
				at = min(at, cursor.positions[0])
			}
		}
	}
	return at
}

func (w *regexpWindowPlan) setLiteralAnchors(tree *syntax.Regexp, limit int) bool {
	anchors := requiredLiteralAnchors(tree)
	if len(anchors) == 0 || len(anchors) > limit {
		return false
	}
	for _, literal := range anchors {
		if !isASCIIString(literal) || len(literal) < minPreFilterAnchorLength {
			return false
		}
		anchor := strings.ToLower(literal[:min(len(literal), regexpWindowAnchorBytes)])
		if !slices.Contains(w.anchors, anchor) {
			w.anchors = append(w.anchors, anchor)
		}
	}
	// Go's Unicode simple-fold orbits add these two non-ASCII members
	// to ASCII letters. Treat each relevant member as an extra candidate.
	for _, anchor := range w.anchors {
		if strings.ContainsRune(anchor, 'k') && !slices.Contains(w.anchors, "K") {
			w.anchors = append(w.anchors, "K")
		}
		if strings.ContainsRune(anchor, 's') && !slices.Contains(w.anchors, "ſ") {
			w.anchors = append(w.anchors, "ſ")
		}
	}
	return true
}

// Prepare view state on the caller goroutine. Workers may share the completed
// position index and window cache, but never build or mutate the index.
func (pf *responsePreFilter) windowMatcher(content string, view *responsePreFilterView, patterns []*compiledPattern, indices []int) func(*compiledPattern, string) []ResponseMatch {
	if view.positions != nil {
		view.positions.index()
	}
	if !view.windowRunReady {
		for _, index := range indices {
			if index >= len(patterns) {
				continue
			}
			if plan := pf.windows[patterns[index].re]; plan != nil && plan.responseWidth.runs != 0 {
				view.maxWindowRun = responseMaxWindowRun(content)
				view.windowRunReady = true
				break
			}
		}
	}
	folded := responseWindowFold(content, view.folded)
	return func(p *compiledPattern, text string) []ResponseMatch {
		return matchResponseWindow(p, text, folded, pf.windows[p.re], view)
	}
}

func responseWindowFold(text, folded string) string {
	if !newResponseFoldView(text, folded).sameOffsets {
		return ""
	}
	return folded
}

func matchResponseWindow(p *compiledPattern, text, folded string, plan *regexpWindowPlan, view *responsePreFilterView) []ResponseMatch {
	if plan == nil || p.responseMemoRegexp != p.re || hasExternalTransferCompanions(p) {
		return matchResponsePattern(p, text)
	}
	if !responsePatternCanMatch(p, text) {
		return nil
	}
	if plan.responseWidth != (responseWindowWidth{}) {
		if ranges, ok := plan.responseRanges(text, folded, view.positions, view.maxWindowRun); ok {
			return responseMatchesAt(p, text, matchRegexpWindows(p.re, text, ranges, view.positions))
		}
	} else if view.positions != nil && view.positions.hits != nil {
		return responseMatchesAt(p, text, plan.findAllWithPositions(p.re, p.re, text, text, view.positions))
	}
	return responseMatchesAt(p, text, p.re.FindAllStringIndex(text, -1))
}
