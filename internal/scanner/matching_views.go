// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"sort"
	"sync"
)

const (
	matchingMaxViewBytes           = 16 << 20
	matchingMaxHits                = 4096
	responseMatchingMaxHits        = 262144
	responseMatchingMaxLiteralHits = 32768
	matchingMaxEdits               = 64
	matchingMaxCells               = 1 << 19
	matchingMaxWindows             = 256
	matchingMaxSegments            = 4096
)

// matchingLiterals uses ASCII-folded byte coordinates. Unicode projections
// must be built by the caller, using the same normalization as its matcher.
type matchingLiterals struct {
	machine  literalAutomaton[int]
	symbols  [256]int16
	ids      map[string]int
	lengths  []int
	longest  int
	response bool
}

func newMatchingLiterals(literals []string) *matchingLiterals {
	if len(literals) == 0 {
		return nil
	}
	p := &matchingLiterals{ids: make(map[string]int)}
	for i := range p.symbols {
		p.symbols[i] = -1
	}
	bytes, width := 0, 0
	var values []string
	for _, literal := range literals {
		key := asciiLowerPreserveLen(literal)
		if _, exists := p.ids[key]; exists || key == "" {
			continue
		}
		if len(key) > matchingMaxCells-bytes {
			continue
		}
		symbols, nextWidth := p.symbols, width
		for at := range len(key) {
			b := key[at]
			if symbols[b] < 0 {
				symbols[b] = int16(nextWidth) // at most one symbol per byte
				nextWidth++
			}
		}
		if (bytes+len(key)+1)*nextWidth > matchingMaxCells {
			continue
		}
		bytes += len(key)
		p.symbols, width = symbols, nextWidth
		p.ids[key] = len(values)
		p.longest = max(p.longest, len(key))
		p.lengths = append(p.lengths, len(key))
		values = append(values, key)
	}
	if width == 0 {
		return nil
	}
	p.machine = newLiteralAutomaton[int](width)
	for id, key := range values {
		p.machine.add(key, &p.symbols, id)
	}
	p.machine.build()
	return p
}

func (p *matchingLiterals) walk(text string, start, end int, visit func(id, start int) bool) bool {
	var state uint32
	for at := start; at < end; at++ {
		symbol := p.symbols[asciiLower(text[at])]
		if symbol < 0 {
			state = 0
			continue
		}
		state = p.machine.step(state, symbol)
		for _, id := range p.machine.out[state] {
			if !visit(id, at+1-p.lengths[id]) {
				return false
			}
		}
	}
	return true
}

// A matchingView identifies one occurrence of a root or transform within a
// scan. Equal bytes at different positions need separate view identities.
// Only byte-level search positions live here; decoder charges, contextual
// validation and findings belong to the caller.
type matchingView struct {
	text                            string
	program                         *matchingLiterals
	parent                          *matchingView
	edits                           []matchingEdit
	children                        map[matchingTransform]*matchingView
	retained                        int
	hits                            [][]int
	truncated                       map[int]bool
	responseChainHits               map[string]responseChainStageHits
	responseChainFiltered           map[responseChainPositionKey][]int
	responseChainWindows            *responseChainWindowMemo
	responseChainSortedHits         int
	responseChainWidths             map[*syntax.Regexp]responseChainMeasuredWidth
	responseChainRuns               *responseDeltaView
	ready                           bool
	windowMu                        sync.Mutex
	windows                         map[windowMatchKey][][2]int
	windowLocations                 int
	ascii, asciiReady               bool
	segments                        []textByteSpan
	segmentsReady, segmentsExceeded bool
}

type matchingTransform uint8

const (
	matchingPrimary matchingTransform = iota
	matchingURL
	matchingHTML
	matchingSubdomain
	matchingSpaced
	matchingLeet
	matchingVowel
)

type matchingEdit struct {
	sourceStart, sourceEnd int
	viewStart, viewEnd     int
}

func newMatchingView(text string, program *matchingLiterals) *matchingView {
	if program == nil || len(text) < regexpWindowMinText || len(text) > matchingMaxViewBytes {
		return nil
	}
	return &matchingView{text: text, program: program, retained: len(text)}
}

func (v *matchingView) derive(text string, edits []matchingEdit) *matchingView {
	if v == nil || len(edits) == 0 || len(edits) > matchingMaxEdits ||
		len(text) < regexpWindowMinText || len(text) > matchingMaxViewBytes {
		return nil
	}
	return &matchingView{text: text, program: v.program, parent: v, edits: edits}
}

func (v *matchingView) isASCII() bool {
	if !v.asciiReady {
		v.ascii = isASCIIString(v.text)
		v.asciiReady = true
	}
	return v.ascii
}

func (v *matchingView) positions(literal string) ([]int, bool) {
	if v == nil {
		return nil, false
	}
	id, ok := v.program.ids[asciiLowerPreserveLen(literal)]
	if !ok {
		return nil, false
	}
	v.index()
	if v.hits == nil || v.truncated[id] {
		return nil, false
	}
	return v.hits[id], true
}

func (v *matchingView) index() {
	if v.ready {
		return
	}
	v.ready = true
	hits := make([][]int, len(v.program.lengths))
	remaining := matchingMaxHits
	if v.program.response {
		remaining = responseMatchingMaxHits
	}
	add := func(id, at int) bool {
		if v.truncated[id] {
			return true
		}
		limit := responseMatchingMaxLiteralHits
		if v.program.lengths[id] == 1 {
			limit = matchingMaxHits
		}
		if remaining == 0 || v.program.response && len(hits[id]) == limit {
			if !v.program.response {
				return false
			}
			if v.truncated == nil {
				v.truncated = make(map[int]bool)
			}
			v.truncated[id] = true
			remaining += len(hits[id])
			hits[id] = nil
			return true
		}
		remaining--
		hits[id] = append(hits[id], at)
		return true
	}
	if v.parent != nil {
		v.parent.index()
	}
	if v.parent == nil || v.program.response && len(v.parent.truncated) > 0 {
		if v.program.walk(v.text, 0, len(v.text), add) {
			v.hits = hits
		}
		return
	}
	if v.parent.hits == nil {
		return
	}
	// A parent hit survives exactly when every byte maps to one unchanged
	// run. Re-scan the edit (a seam for deletions) plus the longest literal
	// minus one byte on each side. Every other child hit was in the parent.
	for id, positions := range v.parent.hits {
		for _, at := range positions {
			if start, ok := v.project(at, at+v.program.lengths[id]); ok && !add(id, start) {
				return
			}
		}
	}
	addChanged := func(id, at int) bool {
		// Hits in an unchanged run have already been counted above.
		_, unchanged := v.sourcePosition(regexpWindowRange{start: at, end: at + v.program.lengths[id]})
		return unchanged || add(id, at)
	}
	padding := v.program.longest - 1
	start, end := 0, 0
	budget := len(v.text)
	for _, edit := range v.edits {
		left := max(0, edit.viewStart-padding)
		right := min(len(v.text), edit.viewEnd+padding)
		if left > end {
			budget -= end - start
			if budget <= 0 || !v.program.walk(v.text, start, end, addChanged) {
				return
			}
			start = left
		}
		end = max(end, right)
	}
	if end-start >= budget || !v.program.walk(v.text, start, end, addChanged) {
		return
	}
	for id, positions := range hits {
		slices.Sort(positions)
		hits[id] = slices.Compact(positions)
	}
	v.hits = hits
}

// project translates a nonempty source interval only when it lies in one
// unchanged run. A zero-width source edit splits a run at the insertion.
func (v *matchingView) project(start, end int) (int, bool) {
	i := sort.Search(len(v.edits), func(i int) bool { return v.edits[i].sourceEnd > start })
	if i < len(v.edits) && v.edits[i].sourceStart < end {
		return 0, false
	}
	if i > 0 {
		edit := v.edits[i-1]
		start += edit.viewEnd - edit.sourceEnd
	}
	return start, true
}

// transformed stores a proved child by the occurrence of its parent and
// transform, independently of content equality with any other child. An
// unexpected second output for the same transform uses ordinary matching.
func (v *matchingView) transformed(kind matchingTransform, text string) *matchingView {
	if v == nil {
		return nil
	}
	if child, found := v.children[kind]; found {
		if child != nil && child.text == text {
			return child
		}
		return nil
	}
	if len(text) > matchingMaxViewBytes-v.retained {
		return nil
	}
	child := v.deriveText(text)
	if child == nil && v.program.response {
		child = newMatchingView(text, v.program)
	}
	if v.children == nil {
		v.children = make(map[matchingTransform]*matchingView)
	}
	v.children[kind] = child
	if child != nil {
		v.retained += len(text)
	}
	return child
}

// deriveText records changed runs for equal-length transforms. When length
// changes, only a common prefix and suffix are reused. The bytes between
// them form one replacement. All comparisons are in emitted byte coordinates.
func (v *matchingView) deriveText(text string) *matchingView {
	if v == nil || len(text) < regexpWindowMinText || len(text) > matchingMaxViewBytes {
		return nil
	}
	if len(text) != len(v.text) {
		start := matchingCommonPrefix(v.text, text)
		a, b := len(v.text), len(text)
		for a > start && b > start && v.text[a-1] == text[b-1] {
			a--
			b--
		}
		if max(a-start, b-start) >= len(text)/8 {
			return nil
		}
		return v.derive(text, []matchingEdit{{start, a, start, b}})
	}
	var edits []matchingEdit
	for at := 0; at < len(text); {
		start := at + matchingCommonPrefix(v.text[at:], text[at:])
		if start == len(text) {
			break
		}
		if len(edits) == matchingMaxEdits {
			return nil
		}
		at = start + 1
		for at < len(text) && v.text[at] != text[at] {
			at++
		}
		edits = append(edits, matchingEdit{start, at, start, at})
	}
	return v.derive(text, edits)
}

func matchingCommonPrefix(a, b string) int {
	const block = 64
	end := min(len(a), len(b))
	at := 0
	for at+block <= end && a[at:at+block] == b[at:at+block] {
		at += block
	}
	for at < end && a[at] == b[at] {
		at++
	}
	return at
}

type windowMatchKey struct {
	re     *regexp.Regexp
	window regexpWindowRange
}

// windowMatches shares regex locations only when the entire independently
// proven regexp window (including its guard bytes) maps to identical bytes.
// Greedy and non-overlapping decisions are recomputed across changed windows.
func (v *matchingView) windowMatches(re *regexp.Regexp, text string, window regexpWindowRange) [][]int {
	key := windowMatchKey{re, window}
	if hits, ok := v.cachedWindow(key); ok {
		return relocateWindowMatches(hits, window.start)
	}
	if v.parent != nil {
		if start, ok := v.sourcePosition(window); ok {
			parentWindow := regexpWindowRange{start, start + window.end - window.start}
			if hits, ok := v.parent.cachedWindow(windowMatchKey{re, parentWindow}); ok {
				return relocateWindowMatches(hits, window.start)
			}
		}
	}
	matches := re.FindAllStringIndex(text[window.start:window.end], -1)
	v.rememberWindow(key, matches)
	return shiftWindowMatches(matches, window.start)
}

func (v *matchingView) cachedWindow(key windowMatchKey) ([][2]int, bool) {
	v.windowMu.Lock()
	defer v.windowMu.Unlock()
	hits, ok := v.windows[key]
	return hits, ok
}

func (v *matchingView) rememberWindow(key windowMatchKey, matches [][]int) {
	v.windowMu.Lock()
	defer v.windowMu.Unlock()
	if _, exists := v.windows[key]; !exists && len(v.windows) < matchingMaxWindows && len(matches) <= matchingMaxHits-v.windowLocations {
		if v.windows == nil {
			v.windows = make(map[windowMatchKey][][2]int)
		}
		var relative [][2]int
		for _, match := range matches {
			relative = append(relative, [2]int{match[0], match[1]})
		}
		v.windows[key] = relative
		v.windowLocations += len(relative)
	}
}

func (v *matchingView) sourcePosition(window regexpWindowRange) (int, bool) {
	i := sort.Search(len(v.edits), func(i int) bool { return v.edits[i].viewEnd > window.start })
	if i < len(v.edits) && v.edits[i].viewStart < window.end {
		return 0, false
	}
	if i == 0 {
		return window.start, true
	}
	edit := v.edits[i-1]
	return window.start + edit.sourceEnd - edit.viewEnd, true
}

func relocateWindowMatches(matches [][2]int, start int) [][]int {
	var out [][]int
	for _, match := range matches {
		out = append(out, []int{match[0] + start, match[1] + start})
	}
	return out
}

func shiftWindowMatches(matches [][]int, start int) [][]int {
	for _, match := range matches {
		match[0] += start
		match[1] += start
	}
	return matches
}

// walkSegments shares only the ordered token spans, after a complete walk.
// Every consumer still observes the token in its own decode mode and order.
func (v *matchingView) walkSegments(text string, visit func(string, int) bool) {
	if v == nil || v.segmentsExceeded {
		walkTextDLPSegments(text, visit)
		return
	}
	if v.segmentsReady {
		for _, span := range v.segments {
			if !visit(text[span.start:span.end], span.start) {
				return
			}
		}
		return
	}
	var spans []textByteSpan
	complete := true
	walkTextDLPSegments(text, func(segment string, start int) bool {
		if len(spans) == matchingMaxSegments {
			v.segmentsExceeded = true
			spans = nil
		}
		if !v.segmentsExceeded {
			spans = append(spans, textByteSpan{start, start + len(segment)})
		}
		complete = visit(segment, start)
		return complete
	})
	if complete && !v.segmentsExceeded {
		v.segments, v.segmentsReady = spans, true
	}
}
