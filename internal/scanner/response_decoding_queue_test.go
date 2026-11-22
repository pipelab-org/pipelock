// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
)

func TestInjectionDecodeQueueSharedLines(t *testing.T) {
	const prefix = "first view\r\n"
	shared := strings.Repeat(strings.Repeat("common text ", 20)+"\r\n", 64)
	first := prefix + shared + "end"
	second := prefix + shared + "new"
	q := newInjectionDecodeQueue("root", true)
	digest, duplicate := q.lookup(first)
	if duplicate {
		t.Fatal("first view was already in the queue")
	}
	stored, cost := q.prepare(first, len(first), true)
	if stored.lines == nil || cost >= len(first) {
		t.Fatalf("repeated text was not shared, cost %d for %d bytes", cost, len(first))
	}
	q.add(stored, injectionDecodeView{text: first, label: "test"}, digest)
	if got := q.views[1].decodeView(); got.text != first || got.label != "test" {
		t.Fatal("packed view did not preserve text and metadata")
	}
	if _, duplicate := q.lookup(first); !duplicate {
		t.Fatal("packed duplicate found no exact entry")
	}
	secondDigest, _ := q.lookup(second)
	q.packed[len(second)][secondDigest] = []int{1}
	if _, duplicate := q.lookup(second); duplicate {
		t.Fatal("a digest hit was accepted for different text")
	}
	linesBefore := len(q.lines)
	overBudget, overCost := q.prepare(second, 100, false)
	if overBudget.lines != nil || overCost <= 100 || len(q.lines) != linesBefore {
		t.Fatal("refused view changed the line table")
	}
	compact, compactCost := q.prepare(second, 4096, false)
	if compact.lines == nil || compactCost > 4096 {
		t.Fatalf("shared second view cost %d bytes", compactCost)
	}
	q.add(compact, injectionDecodeView{text: second}, secondDigest)
	if got := q.views[2].decodeView().text; got != second {
		t.Fatal("second view did not round trip")
	}
}

func TestInjectionDecodeQueueTrailingNewlineAndLineBudget(t *testing.T) {
	text := strings.Repeat(strings.Repeat("common text ", 20)+"\n", 32)
	q := newInjectionDecodeQueue("root", true)
	budget := injectionPackedCost + 32*injectionLineRefCost + 1
	stored, cost := q.prepare(text, budget, false)
	if stored.lines != nil || cost != len(text) || len(q.lines) != 0 {
		t.Fatal("view admitted without room for the new line")
	}
	digest, duplicate := q.lookup(text)
	if duplicate {
		t.Fatal("new view was already queued")
	}
	stored, cost = q.prepare(text, len(text), true)
	if stored.lines == nil || cost >= len(text) {
		t.Fatal("repeated line was not packed")
	}
	q.add(stored, injectionDecodeView{text: text}, digest)
	if got := q.views[1].decodeView().text; got != text {
		t.Fatal("packed view lost its trailing newline")
	}
	if q.equalText(1, text+"\n") {
		t.Fatal("different-size view compared equal")
	}
}

func TestInjectionDecodeQueueFlatViews(t *testing.T) {
	largeLine := strings.Repeat("single line ", 4096)
	for _, share := range []bool{false, true} {
		q := newInjectionDecodeQueue("root", share)
		for _, text := range []string{"short\ntext", largeLine} {
			digest, duplicate := q.lookup(text)
			if duplicate {
				t.Fatal("new flat view was already queued")
			}
			stored, cost := q.prepare(text, len(text), true)
			if stored.lines != nil || cost != len(text) {
				t.Fatalf("flat view retained extra data, cost %d for %d bytes", cost, len(text))
			}
			q.add(stored, injectionDecodeView{text: text}, digest)
			if got := q.views[len(q.views)-1].decodeView().text; got != text {
				t.Fatal("flat view did not round trip")
			}
			if _, duplicate := q.lookup(text); !duplicate {
				t.Fatal("flat duplicate found no exact entry")
			}
		}
	}
}

func TestInjectionDecodeQueueSparseEditLimit(t *testing.T) {
	const padding = " a neutral sentence with enough shared text to align the next punctuation mark."
	for _, count := range []int{matchingMaxEdits, matchingMaxEdits + 1} {
		base := strings.Repeat("!"+padding, count)
		child := strings.Repeat("?"+padding, count)
		aligned := alignInjectionDecodeView(injectionDecodeView{text: base}, 0, child)
		edits, _, ok := responseDeltaEdits(base, child)
		if !ok || len(edits) != count {
			t.Fatalf("expected an alignment with %d edits, got %d", count, len(edits))
		}
		stored, cost := aligned.prepare(child, len(child))
		if packed := cost != 0 && stored.edits != nil; packed != (count == matchingMaxEdits) {
			t.Fatalf("packing %d edits = %t, cost = %d", count, packed, cost)
		}
	}
}
