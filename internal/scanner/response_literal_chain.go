// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	responseChainMaxPaths         = 48
	responseChainMaxRootPaths     = 144
	responseChainMaxChoices       = 96
	responseChainMaxFoldSpellings = 32
	responseChainChoiceWidth      = 64
	responseChainSortedHitBudget  = 65536
	responseChainLocalGapLimit    = 1024
)

// Each regexp path must contain every stage in one branch, in order.
// Unknown bounds widen to the view, and a branch with no usable hit list
// leaves the whole expression eligible for its original matcher.
type responseLiteralChain struct {
	branches []responseChainBranch
	width    responseChainBound
	hasRuns  bool
}

type responseChainBranch struct {
	stages         []responseChainStage
	prefix, suffix responseChainBound
}

type responseChainStage struct {
	literals              []responseChainLiteral
	gap                   responseChainBound // from the preceding literal's end to this start
	width                 responseChainBound
	beforeWord, afterWord bool
	key                   string
}

type responseChainLiteral struct {
	text string
	fold bool
}

// A rune is at least one byte, including Go regexp's treatment of malformed
// UTF-8. On ASCII input every consumed rune is exactly one byte.
type responseChainBound struct {
	minimum        int
	ascii, general responseWindowWidth
	extra          *syntax.Regexp
	allowed        asciiByteSet
	shape          responseChainGapShape
}

func responseChainTreeBound(tree *syntax.Regexp) responseChainBound {
	general, ok := responseRegexpWidth(tree)
	barriers := responseRepeatBarriers(tree)
	allowed := asciiByteSet{^barriers[0], ^barriers[1]}
	bound := responseChainBound{minimum: shapeMinLen(tree), allowed: allowed, shape: responseChainGapShapeFor(tree)}
	if ok {
		bound.general = general
		bound.ascii, _ = responseRegexpWidthForBytes(tree, 1)
	} else {
		bound.extra = tree
	}
	return bound
}

func (b responseChainBound) plus(c responseChainBound) responseChainBound {
	return responseChainBound{
		minimum: b.minimum + c.minimum,
		ascii:   responseWindowWidth{b.ascii.fixed + c.ascii.fixed, b.ascii.runs + c.ascii.runs},
		general: responseWindowWidth{b.general.fixed + c.general.fixed, b.general.runs + c.general.runs},
		extra:   responseChainExtra(syntax.OpConcat, b.extra, c.extra),
		shape:   b.shape.plus(c.shape),
		allowed: asciiByteSet{b.allowed[0] | c.allowed[0], b.allowed[1] | c.allowed[1]},
	}
}

func (b responseChainBound) union(c responseChainBound) responseChainBound {
	return responseChainBound{
		minimum: min(b.minimum, c.minimum),
		ascii:   responseWindowWidth{max(b.ascii.fixed, c.ascii.fixed), max(b.ascii.runs, c.ascii.runs)},
		general: responseWindowWidth{max(b.general.fixed, c.general.fixed), max(b.general.runs, c.general.runs)},
		extra:   responseChainExtra(syntax.OpAlternate, b.extra, c.extra),
		shape:   responseChainGapShape{opaque: true},
		allowed: asciiByteSet{b.allowed[0] | c.allowed[0], b.allowed[1] | c.allowed[1]},
	}
}

func responseChainExtra(op syntax.Op, left, right *syntax.Regexp) *syntax.Regexp {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	return &syntax.Regexp{Op: op, Sub: []*syntax.Regexp{left, right}}
}

func (b responseChainBound) maximum(view *matchingView, maxRun int) (int, bool) {
	w := b.general
	if view.isASCII() {
		w = b.ascii
	}
	if b.extra != nil {
		extra, ok := view.responseChainExtraWidth(b.extra)
		if !ok {
			return 0, false
		}
		w.fixed += extra
	}
	if w.fixed > responseWindowMaxWidth || w.runs > 0 && maxRun > (responseWindowMaxWidth-w.fixed)/w.runs {
		return 0, false
	}
	return w.fixed + w.runs*maxRun, true
}

type responseChainMeasuredWidth struct {
	bytes int
	ok    bool
}

func (v *matchingView) responseChainExtraWidth(tree *syntax.Regexp) (int, bool) {
	if width, ok := v.responseChainWidths[tree]; ok {
		return width.bytes, width.ok
	}
	if v.responseChainWidths == nil {
		v.responseChainWidths = make(map[*syntax.Regexp]responseChainMeasuredWidth)
		v.responseChainRuns = &responseDeltaView{}
	}
	runeWidth := utf8.UTFMax
	if v.isASCII() {
		runeWidth = 1
	}
	width, ok := responseRegexpWidthWith(tree, runeWidth, func(sub *syntax.Regexp) (responseWindowWidth, bool) {
		barriers := responseRepeatBarriers(sub)
		if barriers == (asciiByteSet{}) {
			return responseWindowWidth{}, false
		}
		run := v.responseChainRuns.longestRun(v.text, barriers)
		return responseWindowWidth{fixed: run}, run <= responseWindowMaxWidth
	})
	v.responseChainWidths[tree] = responseChainMeasuredWidth{width.fixed, ok}
	return width.fixed, ok
}

type responseChainPart struct {
	literals []responseChainLiteral
	width    responseChainBound
	word     bool
}

func newResponseLiteralChain(tree *syntax.Regexp) *responseLiteralChain {
	if shapeMinLen(tree) == 0 || regexpStartsAtTextBeginning(tree) {
		return nil
	}
	plan := &responseLiteralChain{width: responseChainTreeBound(tree)}
	plan.hasRuns = plan.width.general.runs > 0
	hasLink := false
	for _, path := range responseChainPaths(tree, false) {
		branch := responseChainPath(path)
		if len(branch.stages) == 0 {
			return nil
		}
		hasLink = hasLink || len(branch.stages) >= 2
		for _, stage := range branch.stages {
			plan.hasRuns = plan.hasRuns || stage.gap.general.runs > 0 || branch.prefix.general.runs > 0 || branch.suffix.general.runs > 0
		}
		plan.branches = append(plan.branches, branch)
	}
	if !hasLink {
		return nil
	}
	return plan
}

// Keep an ordered segment of compulsory literals from each path. Optional
// subtrees become gaps with a zero lower bound, so their presence is immaterial.
func responseChainPath(path []responseChainPart) responseChainBranch {
	var branch responseChainBranch
	var prefix, gap responseChainBound
	for i, part := range path {
		if len(part.literals) == 0 {
			prefix = prefix.plus(part.width)
			gap = gap.plus(part.width)
			continue
		}
		if len(branch.stages) == 0 {
			branch.prefix = prefix
			gap = responseChainBound{}
		}
		stage := responseChainStage{
			literals: part.literals, gap: gap, width: part.width,
			beforeWord: i > 0 && path[i-1].word,
			afterWord:  i+1 < len(path) && path[i+1].word,
		}
		stage.key = stage.hitKey()
		branch.stages = append(branch.stages, stage)
		prefix = prefix.plus(part.width)
		gap = responseChainBound{}
	}
	branch.suffix = gap
	return branch
}

func responseChainPaths(tree *syntax.Regexp, nested bool) [][]responseChainPart {
	switch tree.Op {
	case syntax.OpLiteral:
		return [][]responseChainPart{{{literals: responseChainSpellings(tree), width: responseChainTreeBound(tree)}}}
	case syntax.OpWordBoundary:
		return [][]responseChainPart{{{word: true}}}
	case syntax.OpCapture:
		return responseChainPaths(tree.Sub[0], nested)
	case syntax.OpConcat:
		paths := [][]responseChainPart{nil}
		for _, child := range tree.Sub {
			tails := responseChainPaths(child, true)
			if len(paths)*len(tails) > responseChainMaxPaths {
				if choice := responseChainLeadingChoice(tails); choice != nil {
					tails = [][]responseChainPart{choice}
				} else {
					tails = responseChainGap(child)
				}
			}
			if len(tails) == 1 {
				for i, head := range paths {
					paths[i] = append(head, tails[0]...)
				}
				continue
			}
			var joined [][]responseChainPart
			for _, head := range paths {
				for _, tail := range tails {
					joined = append(joined, append(slices.Clone(head), tail...))
				}
			}
			paths = joined
		}
		return paths
	case syntax.OpAlternate:
		return responseChainAlternates(tree, nested)
	default:
		return responseChainGap(tree)
	}
}

func responseChainGap(tree *syntax.Regexp) [][]responseChainPart {
	return [][]responseChainPart{{{width: responseChainTreeBound(tree)}}}
}

func responseChainAlternates(tree *syntax.Regexp, nested bool) [][]responseChainPart {
	limit := responseChainMaxRootPaths
	if nested {
		limit = responseChainMaxChoices
	}
	var paths [][]responseChainPart
	for _, child := range tree.Sub {
		paths = append(paths, responseChainPaths(child, nested)...)
		if len(paths) > limit {
			return responseChainGap(tree)
		}
	}
	// Compact word and short phrase alternatives into one stage where all
	// branches begin with a literal. Keep their remaining widths as a gap.
	// Longer alternatives retain their own order and distance constraints.
	width := responseChainTreeBound(tree)
	if nested && (len(paths) > responseChainMaxPaths || width.extra == nil && width.general.fixed <= responseChainChoiceWidth && width.general.runs <= 4) {
		if choice := responseChainLeadingChoice(paths); choice != nil {
			return [][]responseChainPart{choice}
		}
	}
	if nested && len(paths) > responseChainMaxPaths {
		return responseChainGap(tree)
	}
	for _, path := range paths {
		if !slices.ContainsFunc(path, func(p responseChainPart) bool { return len(p.literals) > 0 }) {
			return responseChainGap(tree)
		}
	}
	return paths
}

func responseChainLeadingChoice(paths [][]responseChainPart) []responseChainPart {
	var first responseChainPart
	var prefix, rest responseChainBound
	for i, path := range paths {
		at := 0
		var head responseChainBound
		for at < len(path) && len(path[at].literals) == 0 {
			head = head.plus(path[at].width)
			at++
		}
		if at == len(path) {
			return nil
		}
		lead := path[at]
		first.literals = append(first.literals, lead.literals...)
		if len(first.literals) > responseChainMaxChoices {
			return nil
		}
		var tail responseChainBound
		for _, part := range path[at+1:] {
			tail = tail.plus(part.width)
		}
		if i == 0 {
			first.width, prefix, rest = lead.width, head, tail
		} else {
			first.width, prefix, rest = first.width.union(lead.width), prefix.union(head), rest.union(tail)
		}
	}
	var parts []responseChainPart
	if prefix != (responseChainBound{}) {
		parts = append(parts, responseChainPart{width: prefix})
	}
	parts = append(parts, first)
	if rest != (responseChainBound{}) {
		parts = append(parts, responseChainPart{width: rest})
	}
	return parts
}

// The shared automaton ignores ASCII case. Preserve non-ASCII simple-fold
// spellings as separate byte literals and check exact case at use for -i.
// U+FFFD cannot use byte literals because regexp also matches malformed bytes.
func responseChainSpellings(tree *syntax.Regexp) []responseChainLiteral {
	if len(tree.Rune) == 0 || len(tree.Rune) == 1 && (syntax.IsWordChar(tree.Rune[0]) || unicode.IsSpace(tree.Rune[0])) || slices.Contains(tree.Rune, utf8.RuneError) {
		return nil
	}
	fold := tree.Flags&syntax.FoldCase != 0
	if !fold {
		return []responseChainLiteral{{text: string(tree.Rune)}}
	}
	words := []string{""}
	for _, r := range tree.Rune {
		spellings := []rune{responseChainFoldASCII(r)}
		for alt := unicode.SimpleFold(r); alt != r; alt = unicode.SimpleFold(alt) {
			letter := responseChainFoldASCII(alt)
			if !slices.Contains(spellings, letter) {
				spellings = append(spellings, letter)
			}
		}
		if len(words)*len(spellings) > responseChainMaxFoldSpellings {
			return nil
		}
		var extended []string
		for _, word := range words {
			for _, spelling := range spellings {
				extended = append(extended, word+string(spelling))
			}
		}
		words = extended
	}
	literals := make([]responseChainLiteral, 0, len(words))
	for _, word := range words {
		literals = append(literals, responseChainLiteral{text: word, fold: true})
	}
	return literals
}

func responseChainFoldASCII(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

type responseChainHit struct{ start, end int }

type responseChainStageHits struct {
	lists      []responseChainHitList
	sorted     []responseChainHit
	incomplete bool
}

type responseChainHitList struct {
	starts []int
	width  int
}

type responseChainPositionKey struct {
	literal               responseChainLiteral
	beforeWord, afterWord bool
}

func (s responseChainStage) hitKey() string {
	var key strings.Builder
	if s.beforeWord {
		key.WriteByte('b')
	}
	if s.afterWord {
		key.WriteByte('e')
	}
	for _, literal := range s.literals {
		if literal.fold {
			key.WriteByte('f')
		}
		key.WriteString(strconv.Itoa(len(literal.text)))
		key.WriteByte(':')
		key.WriteString(literal.text)
	}
	return key.String()
}

func (s responseChainStage) hits(view *matchingView) responseChainStageHits {
	if hits, ok := view.responseChainHits[s.key]; ok {
		return hits
	}
	var result responseChainStageHits
	for _, literal := range s.literals {
		if view.isASCII() && !isASCIIString(literal.text) {
			continue
		}
		key := responseChainPositionKey{literal, s.beforeWord, s.afterWord}
		hits, ok := view.responseChainPositions(key)
		if !ok {
			result.incomplete = true
		}
		if len(hits) > 0 {
			result.lists = append(result.lists, responseChainHitList{hits, len(literal.text)})
		}
	}
	if len(result.lists) > 1 {
		count := 0
		for _, list := range result.lists {
			count += len(list.starts)
		}
		if count <= responseChainSortedHitBudget-view.responseChainSortedHits {
			result.sorted = responseChainListHits(result.lists, make([]responseChainHit, 0, count))
			view.responseChainSortedHits += len(result.sorted)
		}
	}
	if view.responseChainHits == nil {
		view.responseChainHits = make(map[string]responseChainStageHits)
	}
	view.responseChainHits[s.key] = result
	return result
}

func responseChainListHits(lists []responseChainHitList, dst []responseChainHit) []responseChainHit {
	for _, list := range lists {
		for _, at := range list.starts {
			dst = append(dst, responseChainHit{at, at + list.width})
		}
	}
	if len(lists) > 1 {
		sortResponseChainHits(dst)
	}
	return dst
}

func (v *matchingView) responseChainPositions(key responseChainPositionKey) ([]int, bool) {
	literal := key.literal
	if positions, ok := v.responseChainFiltered[key]; ok {
		return positions, true
	}
	hits, complete := v.positions(literal.text)
	if !complete || len(hits) == 0 || literal.fold && !key.beforeWord && !key.afterWord {
		return hits, complete
	}
	var accepted []int
	for _, at := range hits {
		end := at + len(literal.text)
		if !literal.fold && v.text[at:end] != literal.text ||
			key.beforeWord && !responseChainWordBoundary(v.text, at) ||
			key.afterWord && !responseChainWordBoundary(v.text, end) {
			continue
		}
		accepted = append(accepted, at)
	}
	if v.responseChainFiltered == nil {
		v.responseChainFiltered = make(map[responseChainPositionKey][]int)
	}
	v.responseChainFiltered[key] = accepted
	return accepted, true
}

// Eliminate paths missing a literal group before constructing any of their
// boundary-filtered hit lists. These raw lists only overestimate the hits.
func (s responseChainStage) mayHaveHits(view *matchingView) bool {
	if result, ok := view.responseChainHits[s.key]; ok {
		return result.incomplete || len(result.lists) != 0
	}
	for _, literal := range s.literals {
		if view.isASCII() && !isASCIIString(literal.text) {
			continue
		}
		hits, ok := view.positions(literal.text)
		if !ok || len(hits) > 0 {
			return true
		}
	}
	return false
}

type responseChainScratch struct {
	current, next []responseChainHit
}

type responseChainCandidates struct {
	hits           []responseChainHit
	prefix, suffix responseChainBound
}

// A capped or unavailable hit list is unknown. Widen around that group if
// another group still anchors the path, and fall back if no group survives.
func (b responseChainBranch) completeStages(view *matchingView) ([]responseChainStage, responseChainCandidates, bool) {
	result := responseChainCandidates{prefix: b.prefix, suffix: b.suffix}
	for _, stage := range b.stages {
		if !stage.mayHaveHits(view) {
			return nil, responseChainCandidates{}, true
		}
	}
	incomplete := false
	for _, stage := range b.stages {
		hits := stage.hits(view)
		if len(hits.lists) == 0 && !hits.incomplete {
			return nil, responseChainCandidates{}, true
		}
		incomplete = incomplete || hits.incomplete
	}
	if !incomplete {
		return b.stages, result, true
	}
	var stages []responseChainStage
	var gap responseChainBound
	for _, stage := range b.stages {
		gap = gap.plus(stage.gap)
		hits := stage.hits(view)
		switch {
		case hits.incomplete:
			gap = gap.plus(stage.width)
		default:
			if len(stages) == 0 {
				result.prefix = result.prefix.plus(gap)
				gap = responseChainBound{}
			}
			stage.gap = gap
			stages = append(stages, stage)
			gap = responseChainBound{}
		}
	}
	result.suffix = result.suffix.plus(gap)
	return stages, result, len(stages) > 0
}

// Search backwards so a hit survives only if it reaches a viable hit in the
// next stage. A prefix maximum of reachable ends gives a conservative final
// end in constant time after finding a successor's interval.
func (b responseChainBranch) candidates(view *matchingView, maxRun int, scratch *responseChainScratch) (responseChainCandidates, bool) {
	stages, result, complete := b.completeStages(view)
	if len(stages) == 0 {
		return result, complete
	}
	tail := stages[len(stages)-1].hits(view)
	next := scratch.next[:0]
	if tail.sorted != nil {
		next = append(next, tail.sorted...)
	} else {
		next = responseChainListHits(tail.lists, next)
	}
	responseChainMaxEnds(next)
	current := scratch.current[:0]
	defer func() {
		scratch.next, scratch.current = next, current
	}()
	for i := len(stages) - 2; i >= 0; i-- {
		gap := stages[i+1].gap
		maximum, ok := gap.maximum(view, maxRun)
		if !ok {
			maximum = len(view.text)
		}
		current = current[:0]
		hits := stages[i].hits(view)
		for _, list := range hits.lists {
			first := 0
			for _, at := range list.starts {
				end := at + list.width
				minimum := min(len(view.text)+1, end+gap.minimum)
				for first < len(next) && next[first].start < minimum {
					first++
				}
				if first == len(next) || next[first].start > end+maximum {
					continue
				}
				upper := min(next[len(next)-1].start, end+maximum)
				upper = gap.end(view.text, end, upper)
				if next[first].start <= upper {
					last := first + sort.Search(len(next)-first, func(j int) bool { return next[first+j].start > upper }) - 1
					current = append(current, responseChainHit{at, next[last].end})
				}
			}
		}
		if len(current) == 0 {
			return responseChainCandidates{}, true
		}
		if len(hits.lists) > 1 {
			sortResponseChainHits(current)
		}
		responseChainMaxEnds(current)
		next, current = current, next
	}
	result.hits = next
	return result, true
}

func sortResponseChainHits(hits []responseChainHit) {
	slices.SortFunc(hits, func(a, b responseChainHit) int {
		return a.start - b.start
	})
}

func responseChainMaxEnds(hits []responseChainHit) {
	for i := 1; i < len(hits); i++ {
		hits[i].end = max(hits[i].end, hits[i-1].end)
	}
}

// Bytes disallowed by every element in the gap can only narrow the bound.
// Beyond the inspection limit, keep the original upper limit.
func (b responseChainBound) end(text string, start, upper int) int {
	if b.shape.count > 1 {
		return b.shape.end(text, start, upper)
	}
	if b.allowed != (asciiByteSet{^uint64(0), ^uint64(0)}) {
		for at := start; at < min(upper, start+responseChainLocalGapLimit); at++ {
			if text[at] < utf8.RuneSelf && !b.allowed.has(text[at]) {
				return at
			}
		}
	}
	return upper
}

func (b responseChainBound) start(text string, end, lower int) int {
	if b.allowed != (asciiByteSet{^uint64(0), ^uint64(0)}) {
		for at := end - 1; at >= max(lower, end-responseChainLocalGapLimit); at-- {
			if text[at] < utf8.RuneSelf && !b.allowed.has(text[at]) {
				return at + 1
			}
		}
	}
	return lower
}

func responseChainWordBoundary(text string, at int) bool {
	left := at > 0 && syntax.IsWordChar(rune(text[at-1]))
	right := at < len(text) && syntax.IsWordChar(rune(text[at]))
	return left != right
}

func (p *responseLiteralChain) ranges(view *matchingView, maxRun int, delta *responseDeltaView, scratch *responseChainScratch) ([]regexpWindowRange, bool) {
	var windows []regexpWindowRange
	for _, branch := range p.branches {
		candidates, complete := branch.candidates(view, maxRun, scratch)
		if !complete {
			return nil, false
		}
		if len(candidates.hits) == 0 {
			continue
		}
		prefix, prefixOK := candidates.prefix.maximum(view, maxRun)
		suffix, suffixOK := candidates.suffix.maximum(view, maxRun)
		if !prefixOK || !suffixOK {
			width, bounded := p.width.maximum(view, maxRun)
			if !bounded {
				return nil, false
			}
			if !prefixOK {
				prefix = width
			}
			if !suffixOK {
				suffix = width
			}
		}
		for _, hit := range candidates.hits {
			start := candidates.prefix.start(view.text, hit.start, max(0, hit.start-prefix))
			end := candidates.suffix.end(view.text, hit.end, min(len(view.text), hit.end+suffix))
			if delta == nil || delta.responseChainTouchesEdit(start, end) {
				windows = append(windows, regexpWindowRange{start, end})
			}
		}
	}
	return mergeResponseChainRanges(view.text, windows)
}

// The parent had no match. A child match whose consumed bytes and assertion
// context are unchanged would also have been a parent match. Include edits
// touching either edge, including zero-width deletion seams and text edges.
func (d *responseDeltaView) responseChainTouchesEdit(start, end int) bool {
	i := sort.Search(len(d.edits), func(i int) bool { return d.edits[i].viewEnd >= start-utf8.UTFMax })
	return i < len(d.edits) && d.edits[i].viewStart <= end+utf8.UTFMax
}

// Merge ranges before running FindAll. Each possible match has a full rune
// of context on either side unless it is at the real edge of the input.
func mergeResponseChainRanges(text string, windows []regexpWindowRange) ([]regexpWindowRange, bool) {
	slices.SortFunc(windows, func(a, b regexpWindowRange) int { return a.start - b.start })
	var merged []regexpWindowRange
	covered := 0
	for _, window := range windows {
		var ok bool
		window, ok = responseGuardedRange(text, window)
		if !ok {
			return nil, false
		}
		if n := len(merged); n > 0 && window.start <= merged[n-1].end {
			last := &merged[n-1]
			covered += max(0, window.end-last.end)
			last.end = max(last.end, window.end)
		} else {
			covered += window.end - window.start
			merged = append(merged, window)
		}
		if covered >= len(text) || len(merged) > responseWindowMaxRanges {
			return nil, false
		}
	}
	return merged, true
}

func responseGuardedRange(text string, window regexpWindowRange) (regexpWindowRange, bool) {
	window.start = max(0, window.start-utf8.UTFMax)
	window.end = min(len(text), window.end+utf8.UTFMax)
	return alignResponseRegexpRange(text, window)
}

// If a slice boundary generated a match, retry the whole expression. Such
// a match could hide a real overlapping result even if we discarded it.
func matchResponseChainWindows(re *regexp.Regexp, text string, windows []regexpWindowRange, view *matchingView, captures bool) [][]int {
	var results [][]int
	for _, window := range windows {
		if view != nil && view.responseChainWindows.contains(re, text[window.start:window.end]) {
			continue
		}
		var found [][]int
		if captures {
			found = re.FindAllStringSubmatchIndex(text[window.start:window.end], -1)
			for _, loc := range found {
				for i, at := range loc {
					if at >= 0 {
						loc[i] = at + window.start
					}
				}
			}
		} else {
			found = matchRegexpWindows(re, text, []regexpWindowRange{window}, view)
		}
		for _, loc := range found {
			if responseMatchTouchesWindowEdge(loc, window, len(text)) {
				return responseRegexpLocations(re, text, captures)
			}
		}
		if view != nil && len(found) == 0 {
			view.responseChainWindows.add(re, text[window.start:window.end])
		}
		results = append(results, found...)
	}
	return results
}

func (p *responseLiteralChain) literals() []string {
	var literals []string
	for _, branch := range p.branches {
		for _, stage := range branch.stages {
			for _, literal := range stage.literals {
				literals = append(literals, literal.text)
			}
		}
	}
	return literals
}

type responseChainKey struct {
	pattern    *compiledPattern
	expression *regexp.Regexp
}

type responseChainRanges map[responseChainKey][]regexpWindowRange

func (pf *responsePreFilter) chainRanges(content string, view *responsePreFilterView, patterns []*compiledPattern) responseChainRanges {
	if view.positions == nil || view.outboundMatch != nil || len(pf.chains) == 0 && view.delta == nil {
		return nil
	}
	var ranges responseChainRanges
	var scratch responseChainScratch
	for _, pattern := range patterns {
		if pattern.responseMemoRegexp != pattern.re {
			continue
		}
		expressions := []*regexp.Regexp{pattern.re}
		companions := hasExternalTransferCompanions(pattern)
		if companions {
			expressions = externalTransferExpressions(pattern.re)
		}
		delta := view.delta
		if delta != nil && (!delta.isKnown(pattern) || !responsePatternCanMatch(pattern, delta.parent)) {
			delta = nil
		}
		identical := delta != nil && len(delta.edits) == 0
		// The parent verdict establishes no accepted companion findings.
		// Rejected companion regex hits may still affect FindAll ordering.
		if companions {
			delta = nil
		}
		for _, re := range expressions {
			plan := pf.chains[re]
			var windows []regexpWindowRange
			complete := identical
			if !complete && plan != nil {
				if plan.hasRuns {
					view.prepareWindowRun(content)
				}
				windows, complete = plan.ranges(view.positions, view.maxWindowRun, delta, &scratch)
			}
			if complete {
				if ranges == nil {
					ranges = make(responseChainRanges)
				}
				ranges[responseChainKey{pattern, re}] = windows
			}
		}
	}
	return ranges
}

func (ranges responseChainRanges) patternWindows(p *compiledPattern) ([]regexpWindowRange, bool) {
	windows, complete := ranges[responseChainKey{p, p.re}]
	if !complete || !hasExternalTransferCompanions(p) {
		return windows, complete
	}
	// A companion pattern can be rejected outright only if all three
	// expressions were proven empty. Positive output uses the usual merger.
	for _, re := range externalTransferExpressions(p.re) {
		if rs, ok := ranges[responseChainKey{p, re}]; !ok || len(rs) != 0 {
			return nil, false
		}
	}
	return nil, true
}
