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
// exceptions. A no-op normalization pass can share a proof for identical text.
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
	parent string
	probes [3]responseDeltaProbe

	mu           sync.Mutex
	barriers     map[asciiByteSet]int
	anchoredRuns map[responseDeltaRunAnchor]int
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
	return newResponseDeltaView(known, parent, edits)
}

// Leet and vowel folding substitute only single-byte ASCII characters.
// Reuse the parent's normalized bytes between changes in primary coordinates.
// For matching Unicode transforms such as the spaced view, use an alignment
// of the actual normalized outputs instead.
func mapResponseNormalizedEdits(kind matchingTransform, child, parentMapped string, primary *responseDeltaView) (string, bool) {
	if len(parentMapped) != len(primary.parent) {
		return "", false
	}
	if len(primary.edits) == 0 {
		return parentMapped, true
	}
	unchanged := parentMapped == primary.parent
	for _, edit := range primary.edits {
		if !responseRuneBoundary(primary.parent, edit.sourceStart) || !responseRuneBoundary(primary.parent, edit.sourceEnd) ||
			!responseRuneBoundary(child, edit.viewStart) || !responseRuneBoundary(child, edit.viewEnd) {
			return "", false
		}
		if unchanged {
			replacement := child[edit.viewStart:edit.viewEnd]
			unchanged = normalizeResponseMatchingView(replacement, kind) == replacement
		}
	}
	if unchanged {
		return child, true
	}
	var mapped strings.Builder
	mapped.Grow(len(child))
	end := 0
	for _, edit := range primary.edits {
		replacement := child[edit.viewStart:edit.viewEnd]
		transformed := normalizeResponseMatchingView(replacement, kind)
		if len(transformed) != len(replacement) {
			return "", false
		}
		mapped.WriteString(parentMapped[end:edit.sourceStart])
		mapped.WriteString(transformed)
		end = edit.sourceEnd
	}
	mapped.WriteString(parentMapped[end:])
	return mapped.String(), true
}

func responseRuneBoundary(text string, at int) bool {
	return at == len(text) || utf8.RuneStart(text[at])
}

func newResponseDeltaView(known map[responseNegativeKey]struct{}, parent string, edits []matchingEdit) *responseDeltaView {
	return &responseDeltaView{known: known, edits: edits, parent: parent}
}

type responseDeltaWidth struct {
	width   responseWindowWidth
	tree    *syntax.Regexp // only needed for repeats outside the common ASCII-run set
	anchors map[*syntax.Regexp]responseDeltaRunAnchor
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
	if !ok {
		return responseDeltaWidth{}, false
	}
	return responseDeltaWidth{tree: tree, anchors: responseDeltaRunAnchors(tree)}, true
}

type responseDeltaRunAnchor struct {
	barriers asciiByteSet
	center   byte
}

// Two repetitions of the same class adjacent to a compulsory literal
// such as \S+@\S+ stay in one barrier-free run containing that literal.
// A long run elsewhere cannot lengthen either repetition in that path.
func responseDeltaRunAnchors(tree *syntax.Regexp) map[*syntax.Regexp]responseDeltaRunAnchor {
	var anchors map[*syntax.Regexp]responseDeltaRunAnchor
	var visit func(*syntax.Regexp)
	visit = func(node *syntax.Regexp) {
		if node.Op == syntax.OpConcat {
			for i := 1; i+1 < len(node.Sub); i++ {
				left, middle, right := node.Sub[i-1], node.Sub[i], node.Sub[i+1]
				if middle.Op != syntax.OpLiteral || len(middle.Rune) != 1 || left.Op != syntax.OpPlus || right.Op != syntax.OpPlus {
					continue
				}
				center := middle.Rune[0]
				if center < 0 || center >= utf8.RuneSelf || middle.Flags&syntax.FoldCase != 0 && unicode.SimpleFold(center) != center {
					continue
				}
				literal := byte(center)
				barriers := responseRepeatBarriers(left.Sub[0])
				if barriers == (asciiByteSet{}) || barriers != responseRepeatBarriers(right.Sub[0]) || barriers.has(literal) {
					continue
				}
				if anchors == nil {
					anchors = make(map[*syntax.Regexp]responseDeltaRunAnchor)
				}
				anchor := responseDeltaRunAnchor{barriers, literal}
				anchors[left.Sub[0]], anchors[right.Sub[0]] = anchor, anchor
			}
		}
		for _, sub := range node.Sub {
			visit(sub)
		}
	}
	visit(tree)
	return anchors
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

func (v *responseDeltaView) longestAnchoredRun(text string, anchor responseDeltaRunAnchor) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if longest, ok := v.anchoredRuns[anchor]; ok {
		return longest
	}
	if len(v.anchoredRuns) >= 16 {
		return responseWindowMaxWidth + 1
	}
	longest := 0
	for at := 0; at < len(text); {
		next := strings.IndexByte(text[at:], anchor.center)
		if next < 0 {
			break
		}
		end := at + next + 1
		start := end - 1
		for start > at && !anchor.barriers.has(text[start-1]) && end-start <= responseWindowMaxWidth {
			start--
		}
		for end < len(text) && !anchor.barriers.has(text[end]) && end-start <= responseWindowMaxWidth {
			end++
		}
		longest = max(longest, end-start)
		if longest > responseWindowMaxWidth {
			break
		}
		at = end + 1
	}
	if v.anchoredRuns == nil {
		v.anchoredRuns = make(map[responseDeltaRunAnchor]int)
	}
	v.anchoredRuns[anchor] = longest
	return longest
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
	ranges, ok := v.plannedRanges(text, plan)
	if !ok {
		return nil, false
	}
	return v.matchRanges(p, text, ranges)
}

func (v *responseDeltaView) plannedRanges(text string, plan responseDeltaWidth) ([]regexpWindowRange, bool) {
	width := plan.width
	if plan.tree != nil {
		var ok bool
		width, ok = responseRegexpWidthWith(plan.tree, utf8.UTFMax, func(sub *syntax.Regexp) (responseWindowWidth, bool) {
			barriers := responseRepeatBarriers(sub)
			if barriers == (asciiByteSet{}) {
				return responseWindowWidth{}, false
			}
			var run int
			if anchor, ok := plan.anchors[sub]; ok {
				run = v.longestAnchoredRun(text, anchor)
			} else {
				run = v.longestRun(text, barriers)
			}
			return responseWindowWidth{fixed: run}, run <= responseWindowMaxWidth
		})
		if !ok {
			return nil, false
		}
	}
	return v.ranges(text, width)
}

// A repeat bounded by its byte barriers can be measured near the edit. The
// measured bound also applies to the part of any match inside the probe:
// slicing a valid path can only shorten each literal, class or repetition.
// If a match could leave the probe, it would have to consume at least radius
// minus one rune of assertion context before reaching the artificial edge.
func (v *responseDeltaView) localRanges(text string, plan responseDeltaWidth) ([]regexpWindowRange, bool) {
	if plan.tree == nil && plan.width.runs == 0 {
		return v.ranges(text, plan.width)
	}
	for i, radius := range [...]int{256, 1024, 4096} {
		probe := &v.probes[i]
		if !probe.ready {
			probe.ranges, probe.ok = responseDeltaRanges(text, v.edits, radius)
			probe.ok = probe.ok && responseChainWindowBytes(probe.ranges) <= len(text)/8
			probe.ready = true
		}
		if !probe.ok {
			break
		}
		width := plan.width
		if plan.tree != nil {
			var ok bool
			width, ok = responseRegexpWidthWith(plan.tree, utf8.UTFMax, func(sub *syntax.Regexp) (responseWindowWidth, bool) {
				barriers := responseRepeatBarriers(sub)
				if barriers == (asciiByteSet{}) {
					return responseWindowWidth{}, false
				}
				if anchor, ok := plan.anchors[sub]; ok {
					return responseWindowWidth{fixed: v.longestAnchoredRun(text, anchor)}, true
				}
				return responseWindowWidth{fixed: probe.longestRun(text, barriers)}, true
			})
			if !ok {
				return nil, false
			}
		}
		consumed := width.fixed
		if width.runs != 0 {
			barriers := asciiByteSet{^responseWindowRunBytes[0], ^responseWindowRunBytes[1]}
			consumed += width.runs * probe.longestRun(text, barriers)
		}
		if consumed > 0 && consumed+utf8.UTFMax < radius {
			return responseDeltaRanges(text, v.edits, consumed+utf8.UTFMax)
		}
	}
	return nil, false
}

type responseDeltaProbe struct {
	ranges []regexpWindowRange
	runs   map[asciiByteSet]int
	ready  bool
	ok     bool
}

func (p *responseDeltaProbe) longestRun(text string, barriers asciiByteSet) int {
	if run, ok := p.runs[barriers]; ok {
		return run
	}
	if len(p.runs) >= 16 {
		return responseWindowMaxWidth + 1
	}
	longest := 0
	for _, window := range p.ranges {
		run := 0
		for i := window.start; i < window.end; i++ {
			if barriers.has(text[i]) {
				longest = max(longest, run)
				run = 0
			} else {
				run++
			}
		}
		longest = max(longest, run)
	}
	if p.runs == nil {
		p.runs = make(map[asciiByteSet]int)
	}
	p.runs[barriers] = longest
	return longest
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
	ranges, ok := v.ranges(text, width)
	if !ok {
		return nil, false
	}
	return v.matchRanges(p, text, ranges)
}

func (v *responseDeltaView) ranges(text string, width responseWindowWidth) ([]regexpWindowRange, bool) {
	consumed := width.fixed
	if width.runs > 0 {
		barriers := asciiByteSet{^responseWindowRunBytes[0], ^responseWindowRunBytes[1]}
		maxRun := v.longestRun(text, barriers)
		if maxRun > (responseWindowMaxWidth-width.fixed)/width.runs {
			return nil, false
		}
		consumed += width.runs * maxRun
	}
	if consumed == 0 || consumed > responseWindowMaxWidth {
		return nil, false
	}
	return responseDeltaRanges(text, v.edits, consumed+utf8.UTFMax)
}

func (*responseDeltaView) matchRanges(p *compiledPattern, text string, ranges []regexpWindowRange) ([]ResponseMatch, bool) {
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
