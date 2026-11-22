// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp/syntax"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

const (
	responseDeltaAnchor   = 16
	responseDeltaLook     = 64
	responseDeltaMaxEdits = 1024
)

// responseDeltaEdits is an alignment, not a minimal diff. Every retained run
// is checked for byte equality. A wrong resynchronization can only increase
// the work or cause fallback; it cannot certify different bytes as equal.
func responseDeltaEdits(parent, child string) ([]matchingEdit, int, bool) {
	if parent == child {
		return nil, 0, true
	}
	limit := max(len(parent), len(child)) / 4
	if delta := len(parent) - len(child); delta > limit || -delta > limit {
		return nil, 0, false
	}
	var edits []matchingEdit
	changed := 0
	searchLeft := len(parent) + len(child)
	p, c := 0, 0
	for {
		equal := responseDeltaPrefix(parent[p:], child[c:])
		p, c = p+equal, c+equal
		if p == len(parent) && c == len(child) {
			return edits, changed, true
		}
		if len(edits) == responseDeltaMaxEdits {
			return nil, 0, false
		}
		dp, dc := responseDeltaResync(parent[p:], child[c:], &searchLeft)
		changed += max(dp, dc)
		if changed > limit {
			return nil, 0, false
		}
		edits = append(edits, matchingEdit{sourceStart: p, sourceEnd: p + dp, viewStart: c, viewEnd: c + dc})
		p, c = p+dp, c+dc
	}
}

func responseDeltaPrefix(a, b string) int {
	const block = 128
	n := min(len(a), len(b))
	i := 0
	for ; i+block <= n && a[i:i+block] == b[i:i+block]; i += block {
	}
	for ; i < n && a[i] == b[i]; i++ {
	}
	return i
}

// Prefer nearby replacements. A bounded number of bytes can also be searched
// for longer deletions or insertions, such as an omitted HTML token.
func responseDeltaResync(parent, child string, searchLeft *int) (int, int) {
	if len(parent) >= responseDeltaAnchor && len(child) >= responseDeltaAnchor {
		bestP, bestC := responseDeltaLook, responseDeltaLook
		local := min(len(parent), responseDeltaLook+responseDeltaAnchor)
		for c := 0; c < min(responseDeltaLook, len(child)-responseDeltaAnchor+1, bestP+bestC); c++ {
			p := strings.Index(parent[:local], child[c:c+responseDeltaAnchor])
			if p >= 0 && p+c < bestP+bestC {
				bestP, bestC = p, c
			}
		}
		if bestP+bestC < 2*responseDeltaLook {
			return bestP, bestC
		}
		if end := min(len(parent), *searchLeft); end >= responseDeltaAnchor {
			*searchLeft -= end
			if p := strings.Index(parent[:end], child[:responseDeltaAnchor]); p >= 0 {
				return p, 0
			}
		}
		if end := min(len(child), *searchLeft); end >= responseDeltaAnchor {
			*searchLeft -= end
			if c := strings.Index(child[:end], parent[:responseDeltaAnchor]); c >= 0 {
				return 0, c
			}
		}
	}
	// A shared tail is useful even if an interior search found no anchor.
	p, c := len(parent), len(child)
	for p > 0 && c > 0 && parent[p-1] == child[c-1] {
		p, c = p-1, c-1
	}
	return p, c
}

// A negative is captured before suppression, defensive filtering or observe
// exceptions. A no-op normalization pass has no proof unless it actually ran.
type responseDeltaProof [matchingVowel + 1]map[responseNegativeKey]struct{}

func (p responseDeltaProof) hasNegatives() bool {
	for _, negatives := range p {
		if len(negatives) != 0 {
			return true
		}
	}
	return false
}

func newResponseDeltaParent(view injectionDecodeView) *responseDeltaParent {
	return &responseDeltaParent{proof: view.proof, raw: exciseVerifiedImageDataURLs(view.text)}
}

type responseDeltaParent struct {
	proof responseDeltaProof
	raw   string
	text  [matchingVowel + 1]string
	ready [matchingVowel + 1]bool
}

func (p *responseDeltaParent) matchingText(kind matchingTransform) string {
	if !p.ready[kind] {
		switch kind {
		case matchingPrimary:
			p.text[kind] = normalize.ForMatching(p.raw)
		case matchingSpaced:
			p.text[kind] = normalize.ForMatchingSpaced(p.raw)
		case matchingLeet:
			p.text[kind] = normalize.Leetspeak(p.matchingText(matchingPrimary))
		case matchingVowel:
			p.text[kind] = normalize.FoldVowels(p.matchingText(matchingPrimary))
		}
		p.ready[kind] = true
	}
	return p.text[kind]
}

type responseDeltaView struct {
	known  map[responseNegativeKey]struct{}
	edits  []matchingEdit
	maxRun int
	parent string

	mu       sync.Mutex
	barriers map[asciiByteSet]int
}

func (p *responseDeltaParent) view(kind matchingTransform, child string) *responseDeltaView {
	known := p.proof[kind]
	if len(known) == 0 || len(child) < responseMemoMinBytes {
		return nil
	}
	parent := p.matchingText(kind)
	edits, _, ok := responseDeltaEdits(parent, child)
	if !ok {
		return nil
	}
	var maxRun int
	if len(edits) != 0 {
		maxRun = responseMaxWindowRun(child)
	}
	return &responseDeltaView{known: known, edits: edits, maxRun: maxRun, parent: parent}
}

type responseDeltaWidth struct {
	width responseWindowWidth
	tree  *syntax.Regexp // only needed for repeats outside the common ASCII-run set
}

func newResponseDeltaWidth(tree *syntax.Regexp) (responseDeltaWidth, bool) {
	if shapeMinLen(tree) == 0 {
		return responseDeltaWidth{}, false
	}
	if width, ok := responseRegexpWidth(tree); ok {
		return responseDeltaWidth{width: width}, true
	}
	_, ok := responseRegexpWidthWith(tree, utf8.UTFMax, func(sub *syntax.Regexp) (responseWindowWidth, bool) {
		return responseWindowWidth{fixed: 1}, responseRepeatBarriers(sub) != (asciiByteSet{})
	})
	return responseDeltaWidth{tree: tree}, ok
}

// The complement of possible consumed ASCII bytes is a set of barriers.
// Every iteration of this subexpression stays within one barrier-free run,
// even when the arm alternates, is nested, or contains empty assertions.
func responseRepeatBarriers(tree *syntax.Regexp) asciiByteSet {
	var bytes asciiByteSet
	switch tree.Op {
	case syntax.OpLiteral:
		for _, r := range tree.Rune {
			if r < utf8.RuneSelf {
				bytes.addRune(r)
			}
			if tree.Flags&syntax.FoldCase != 0 {
				for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
					if folded < utf8.RuneSelf {
						bytes.addRune(folded)
					}
				}
			}
		}
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		bytes = regexpClassBytes(tree)
	case syntax.OpCapture, syntax.OpConcat, syntax.OpAlternate, syntax.OpQuest, syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		var barriers asciiByteSet
		barriers[0], barriers[1] = ^uint64(0), ^uint64(0)
		for _, sub := range tree.Sub {
			next := responseRepeatBarriers(sub)
			barriers[0] &= next[0]
			barriers[1] &= next[1]
		}
		return barriers
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpNoMatch:
	default:
		return asciiByteSet{}
	}
	return asciiByteSet{^bytes[0], ^bytes[1]}
}

func (v *responseDeltaView) longestRun(text string, barriers asciiByteSet) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if n, ok := v.barriers[barriers]; ok {
		return n
	}
	if len(v.barriers) >= 16 {
		return responseWindowMaxWidth + 1
	}
	longest, run := 0, 0
	for i := range len(text) {
		if barriers.has(text[i]) {
			longest = max(longest, run)
			run = 0
		} else {
			run++
			if run > responseWindowMaxWidth {
				break
			}
		}
	}
	if v.barriers == nil {
		v.barriers = make(map[asciiByteSet]int)
	}
	v.barriers[barriers] = max(longest, run)
	return v.barriers[barriers]
}

func (v *responseDeltaView) matchPlanned(p *compiledPattern, text string, plan responseDeltaWidth) ([]ResponseMatch, bool) {
	if len(p.requiredLiteralsAny) != 0 {
		if !responsePatternCanMatch(p, text) {
			return nil, true
		}
		// A parent miss due only to an extrinsic gate is not a regexp miss.
		if !responsePatternCanMatch(p, v.parent) {
			return nil, false
		}
	}
	if !v.isKnown(p) {
		return nil, false
	}
	if len(v.edits) == 0 {
		return nil, true
	}
	width := plan.width
	if plan.tree != nil {
		var ok bool
		width, ok = responseRegexpWidthWith(plan.tree, utf8.UTFMax, func(sub *syntax.Regexp) (responseWindowWidth, bool) {
			barriers := responseRepeatBarriers(sub)
			if barriers == (asciiByteSet{}) {
				return responseWindowWidth{}, false
			}
			run := v.longestRun(text, barriers)
			return responseWindowWidth{fixed: run}, run <= responseWindowMaxWidth
		})
		if !ok {
			return nil, false
		}
	}
	return v.match(p, text, width)
}

func (v *responseDeltaView) isKnown(p *compiledPattern) bool {
	key, ok := responseNegativePatternKey(p)
	_, known := v.known[key]
	return ok && known
}

func (v *responseDeltaView) match(p *compiledPattern, text string, width responseWindowWidth) ([]ResponseMatch, bool) {
	if !v.isKnown(p) {
		return nil, false
	}
	if len(v.edits) == 0 {
		return nil, true
	}
	if width.runs != 0 && v.maxRun > (responseWindowMaxWidth-width.fixed)/width.runs {
		return nil, false
	}
	consumed := width.fixed + width.runs*v.maxRun
	if consumed == 0 || consumed > responseWindowMaxWidth {
		return nil, false
	}
	ranges, ok := responseDeltaRanges(text, v.edits, consumed+utf8.UTFMax)
	if !ok {
		return nil, false
	}
	var locations [][]int
	for _, window := range ranges {
		found := p.re.FindAllStringIndex(text[window.start:window.end], -1)
		for _, loc := range found {
			// The only assertions whose answers could change on slicing
			// are at its artificial ends. A reported match there may also
			// have suppressed a real overlapping match, so retry whole.
			if (window.start != 0 && loc[0] == 0) ||
				(window.end != len(text) && loc[1] == window.end-window.start) {
				return nil, false
			}
		}
		locations = append(locations, shiftWindowMatches(found, window.start)...)
	}
	return responseMatchesAt(p, text, locations), true
}

func responseDeltaRanges(text string, edits []matchingEdit, width int) ([]regexpWindowRange, bool) {
	var ranges []regexpWindowRange
	covered := 0
	for _, edit := range edits {
		start, end := max(0, edit.viewStart-width), min(len(text), edit.viewEnd+width)
		window, ok := alignResponseRegexpRange(text, regexpWindowRange{start, end})
		if !ok {
			return nil, false
		}
		start, end = window.start, window.end
		if last := len(ranges) - 1; last >= 0 && start <= ranges[last].end {
			covered += max(0, end-ranges[last].end)
			ranges[last].end = max(end, ranges[last].end)
		} else {
			covered += end - start
			ranges = append(ranges, regexpWindowRange{start, end})
		}
		if covered > len(text)/2 {
			return nil, false
		}
	}
	return ranges, true
}

// Avoid splitting UTF-8 at slice edges. Very long runs of continuation
// bytes are inconclusive and fall back to the whole matcher.
func alignResponseRegexpRange(text string, window regexpWindowRange) (regexpWindowRange, bool) {
	for i := 0; window.start > 0 && window.start < len(text) && !utf8.RuneStart(text[window.start]); i++ {
		if i == utf8.UTFMax {
			return regexpWindowRange{}, false
		}
		window.start--
	}
	for i := 0; window.end < len(text) && !utf8.RuneStart(text[window.end]); i++ {
		if i == utf8.UTFMax {
			return regexpWindowRange{}, false
		}
		window.end++
	}
	return window, true
}

func responseMatchTouchesWindowEdge(loc []int, window regexpWindowRange, textLen int) bool {
	return window.start != 0 && loc[0] == window.start || window.end != textLen && loc[1] == window.end
}
