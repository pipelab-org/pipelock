// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "strings"

// injectionDecodeQueue retains exact views. Outbound scans can keep shared lines
// instead of independent whole-text copies. Inbound scans can retain sparse
// substitutions against an earlier view. Decoders still see the exact text.
type injectionDecodeQueue struct {
	views  []storedInjectionView
	flat   map[string]struct{}
	packed map[[32]byte][]int
	lines  map[string]string
	first  map[string]int
}

type storedInjectionView struct {
	injectionDecodeView
	lines  []string
	size   int
	parent int
	edits  []injectionDecodeEdit
}

type injectionDecodeEdit struct {
	start, end  int
	replacement string
}

func (q *injectionDecodeQueue) decodeView(index int) injectionDecodeView {
	stored := q.views[index]
	view := stored.decodeView()
	if stored.edits == nil {
		return view
	}
	var text strings.Builder
	text.Grow(stored.size)
	q.walkViewText(index, 0, stored.size, func(part string) bool {
		text.WriteString(part)
		return true
	})
	view.text = text.String()
	return view
}

// Visit only the requested output range of a packed view. Translate the
// unchanged spans back to their source offsets without joining intermediate
// ancestors or allocating a string just to compare a digest candidate.
func (q *injectionDecodeQueue) walkViewText(index, start, end int, visit func(string) bool) bool {
	stored := &q.views[index]
	if stored.lines != nil {
		at := 0
		for _, line := range stored.lines {
			next := at + len(line)
			if next > start && !visit(line[max(start-at, 0):min(end-at, len(line))]) {
				return false
			}
			if next >= end {
				return true
			}
			at = next
		}
		return true
	}
	if stored.edits == nil {
		return visit(stored.text[start:end])
	}
	at, source := 0, 0
	for _, edit := range stored.edits {
		unchanged := at + edit.start - source
		if unchanged > start && unchanged > at && !q.walkViewText(stored.parent, source+max(start-at, 0), source+min(end-at, unchanged-at), visit) {
			return false
		}
		if unchanged >= end {
			return true
		}
		next := unchanged + len(edit.replacement)
		if next > start && next > unchanged && !visit(edit.replacement[max(start-unchanged, 0):min(end-unchanged, len(edit.replacement))]) {
			return false
		}
		if next >= end {
			return true
		}
		at, source = next, edit.end
	}
	return q.walkViewText(stored.parent, source+max(start-at, 0), source+end-at, visit)
}

func (v storedInjectionView) decodeView() injectionDecodeView {
	view := v.injectionDecodeView
	if v.lines != nil {
		view.text = strings.Join(v.lines, "")
	}
	return view
}

func newInjectionDecodeQueue(root string, shareLines bool) injectionDecodeQueue {
	q := injectionDecodeQueue{
		views:  []storedInjectionView{{injectionDecodeView: injectionDecodeView{text: root}}},
		flat:   map[string]struct{}{root: {}},
		packed: make(map[[32]byte][]int),
	}
	if shareLines {
		q.lines = make(map[string]string)
	} else {
		q.first = make(map[string]int)
	}
	return q
}

func (q *injectionDecodeQueue) lookup(text string) (digest [32]byte, duplicate bool) {
	if _, exists := q.flat[text]; exists || text == "" {
		return digest, true
	}
	if len(text) < injectionLineMinView {
		return digest, false
	}
	digest = sum256String(text)
	for _, index := range q.packed[digest] {
		if q.equalText(index, text) {
			return digest, true
		}
	}
	return digest, false
}

func (q *injectionDecodeQueue) equalText(index int, text string) bool {
	return q.views[index].size == len(text) && q.walkViewText(index, 0, len(text), func(part string) bool {
		if !strings.HasPrefix(text, part) {
			return false
		}
		text = text[len(part):]
		return true
	}) && text == ""
}

const (
	injectionLineMinView = 4096
	injectionLineRefCost = 16
	injectionLineMapCost = 64
	injectionPackedCost  = 128
)

func (q *injectionDecodeQueue) prepare(text string, remaining int, seed bool) (storedInjectionView, int) {
	flat := storedInjectionView{size: len(text)}
	if q.lines == nil || len(text) < injectionLineMinView {
		return flat, len(text)
	}
	count := strings.Count(text, "\n")
	if text[len(text)-1] != '\n' {
		count++
	}
	cost := injectionPackedCost + count*injectionLineRefCost
	limit := min(remaining, len(text)-1)
	if seed {
		// Allow a shallow view to seed the table with modest metadata overhead
		// while keeping its representation within the per-view byte ceiling.
		limit = min(remaining, len(text)+len(text)/4)
	}
	if count < 2 || cost > limit {
		return flat, len(text)
	}
	fresh := make(map[string]struct{})
	for line := range strings.SplitAfterSeq(text, "\n") {
		if _, exists := q.lines[line]; exists || line == "" {
			continue
		}
		if _, exists := fresh[line]; !exists {
			cost += len(line) + injectionLineMapCost
			if cost > limit {
				return flat, len(text)
			}
			fresh[line] = struct{}{}
		}
	}
	lines := make([]string, 0, count)
	for line := range strings.SplitAfterSeq(text, "\n") {
		if line == "" {
			continue
		}
		saved, exists := q.lines[line]
		if !exists {
			saved = strings.Clone(line)
			q.lines[saved] = saved
		}
		lines = append(lines, saved)
	}
	return storedInjectionView{lines: lines, size: len(text)}, cost
}

type injectionDecodeAlignment struct {
	base    injectionDecodeView
	index   int
	edits   []matchingEdit
	changed int
	ok      bool
}

func alignInjectionDecodeView(base injectionDecodeView, index int, text string) injectionDecodeAlignment {
	edits, changed, ok := responseDeltaEdits(base.text, text)
	return injectionDecodeAlignment{base: base, index: index, edits: edits, changed: changed, ok: ok}
}

const injectionSparseEditCost = 32 // two offsets and a string

func (a injectionDecodeAlignment) cost() int {
	if !a.ok {
		return maxDecodeTotalBytes + 1
	}
	return a.changed + len(a.edits)*injectionSparseEditCost
}

// A second transform of already-decoded text can be closer to the earlier
// result of that transform than to its own parent. Both alignments verify
// every shared byte. The base is an implementation detail of the storage
// and matcher, independent of the decode lineage attached to the view.
func (q *injectionDecodeQueue) align(head int, parent, view injectionDecodeView) injectionDecodeAlignment {
	nearest := alignInjectionDecodeView(parent, head, view.text)
	if index, ok := q.first[view.label]; ok && index != head {
		base := q.decodeView(index)
		// Keep expansion of packed views within the same decode depth cap.
		if base.depth <= parent.depth {
			alternate := alignInjectionDecodeView(base, index, view.text)
			if alternate.cost() < nearest.cost() {
				return alternate
			}
		}
	}
	return nearest
}

// A packed child retains only its replacement bytes and edit records. Include
// removed bytes in the charge and keep the flat path when packing costs more.
func (a injectionDecodeAlignment) prepare(text string, remaining int) (storedInjectionView, int) {
	cost := injectionPackedCost + a.cost()
	if len(a.edits) == 0 || cost >= len(text) || cost > remaining {
		return storedInjectionView{}, 0
	}
	stored := storedInjectionView{parent: a.index, size: len(text), edits: make([]injectionDecodeEdit, 0, len(a.edits))}
	for _, edit := range a.edits {
		stored.edits = append(stored.edits, injectionDecodeEdit{
			start: edit.sourceStart, end: edit.sourceEnd, replacement: strings.Clone(text[edit.viewStart:edit.viewEnd]),
		})
	}
	return stored, cost
}

func (q *injectionDecodeQueue) add(stored storedInjectionView, view injectionDecodeView, digest [32]byte) {
	if stored.lines == nil && stored.edits == nil {
		q.flat[view.text] = struct{}{}
	} else {
		q.packed[digest] = append(q.packed[digest], len(q.views))
		view.text = ""
	}
	stored.injectionDecodeView = view
	q.views = append(q.views, stored)
}
