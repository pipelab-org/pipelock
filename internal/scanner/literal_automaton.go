// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "math"

// literalAutomaton is an Aho-Corasick machine over a caller-supplied alphabet.
// Encoded reassembly walks a projected alphabet; matching views walk bytes.
type literalAutomaton[T comparable] struct {
	next     []uint32
	out      [][]T
	width    int
	building []literalBuildNode[T]
	edges    []literalBuildEdge
}

type literalBuildNode[T comparable] struct {
	edge int
	out  []T
}

type literalBuildEdge struct {
	next   int
	value  int16
	target uint32
}

func newLiteralAutomaton[T comparable](width int) literalAutomaton[T] {
	return literalAutomaton[T]{width: width, building: []literalBuildNode[T]{{}}}
}

func (a *literalAutomaton[T]) add(value string, alphabet *[256]int16, output T) {
	var state uint32
	for i := range len(value) {
		symbol := alphabet[value[i]]
		if symbol < 0 {
			panic("literal is outside its alphabet")
		}
		var next uint32
		for at := a.building[state].edge; at > 0; at = a.edges[at-1].next {
			if edge := a.edges[at-1]; edge.value == symbol {
				next = edge.target
				break
			}
		}
		if next == 0 {
			if len(a.building) > math.MaxInt32 {
				panic("literal automaton exceeds address space")
			}
			next = uint32(len(a.building) & math.MaxInt32)
			a.building = append(a.building, literalBuildNode[T]{})
			a.edges = append(a.edges, literalBuildEdge{a.building[state].edge, symbol, next})
			a.building[state].edge = len(a.edges)
		}
		state = next
	}
	for _, old := range a.building[state].out {
		if old == output {
			return
		}
	}
	a.building[state].out = append(a.building[state].out, output)
}

func (a *literalAutomaton[T]) build() {
	// Compile the sparse trie into a dense transition table once.
	a.next = make([]uint32, len(a.building)*a.width)
	a.out = make([][]T, len(a.building))
	for id, node := range a.building {
		a.out[id] = node.out
		for at := node.edge; at > 0; at = a.edges[at-1].next {
			edge := a.edges[at-1]
			a.next[id*a.width+int(edge.value)] = edge.target
		}
	}
	a.building, a.edges = nil, nil
	fail := make([]uint32, len(a.out))
	var queue []uint32
	for _, n := range a.next[:a.width] {
		if n != 0 {
			queue = append(queue, n)
		}
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		row := int(state) * a.width
		failureRow := int(fail[state]) * a.width
		for c := range a.width {
			next := a.next[row+c]
			fallback := a.next[failureRow+c]
			if next == 0 {
				a.next[row+c] = fallback
				continue
			}
			fail[next] = fallback
			a.out[next] = append(a.out[next], a.out[fallback]...)
			queue = append(queue, next)
		}
	}
}

func (a *literalAutomaton[T]) step(state uint32, symbol int16) uint32 {
	return a.next[int(state)*a.width+int(symbol)]
}
