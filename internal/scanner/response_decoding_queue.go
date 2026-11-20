// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "strings"

// injectionDecodeQueue retains exact views. Outbound scans can keep shared lines
// instead of independent whole-text copies. Decoding and matching still see
// the whole view, including unchanged line delimiters and across-line matches.
type injectionDecodeQueue struct {
	views  []storedInjectionView
	flat   map[string]struct{}
	packed map[[32]byte][]int
	lines  map[string]string
}

type storedInjectionView struct {
	injectionDecodeView
	lines []string
	size  int
}

func (v storedInjectionView) decodeView() injectionDecodeView {
	view := v.injectionDecodeView
	if v.lines != nil {
		view.text = strings.Join(v.lines, "")
	}
	return view
}

func (v storedInjectionView) equalText(text string) bool {
	if v.size != len(text) {
		return false
	}
	for _, line := range v.lines {
		if !strings.HasPrefix(text, line) {
			return false
		}
		text = text[len(line):]
	}
	return text == ""
}

func newInjectionDecodeQueue(root string, shareLines bool) injectionDecodeQueue {
	q := injectionDecodeQueue{
		views: []storedInjectionView{{injectionDecodeView: injectionDecodeView{text: root}}},
		flat:  map[string]struct{}{root: {}},
	}
	if shareLines {
		q.packed = make(map[[32]byte][]int)
		q.lines = make(map[string]string)
	}
	return q
}

func (q *injectionDecodeQueue) lookup(text string) (digest [32]byte, duplicate bool) {
	if _, exists := q.flat[text]; exists || text == "" {
		return digest, true
	}
	if q.packed == nil || len(text) < injectionLineMinView {
		return digest, false
	}
	digest = sum256String(text)
	for _, index := range q.packed[digest] {
		if q.views[index].equalText(text) {
			return digest, true
		}
	}
	return digest, false
}

const (
	injectionLineMinView = 4096
	injectionLineRefCost = 16
	injectionLineMapCost = 64
	injectionPackedCost  = 128
)

func (q *injectionDecodeQueue) prepare(text string, remaining int, seed bool) (storedInjectionView, int) {
	flat := storedInjectionView{size: len(text)}
	if q.packed == nil || len(text) < injectionLineMinView {
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

func (q *injectionDecodeQueue) add(stored storedInjectionView, view injectionDecodeView, digest [32]byte) {
	if stored.lines == nil {
		q.flat[view.text] = struct{}{}
	} else {
		q.packed[digest] = append(q.packed[digest], len(q.views))
		view.text = ""
	}
	stored.injectionDecodeView = view
	q.views = append(q.views, stored)
}
