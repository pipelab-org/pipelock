// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"math"
	"regexp/syntax"
	"strings"
	"unicode"
)

type reassemblyCodec struct {
	name, alphabet string
	width, quantum int
	values         [256]int16
}

var reassemblyCodecs = func() [5]reassemblyCodec {
	a := [5]reassemblyCodec{{name: "hex", alphabet: "0123456789abcdef", width: 4, quantum: 2}, {name: "base64", alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", width: 6, quantum: 4}, {name: "base64url", alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", width: 6, quantum: 4}, {name: "base32", alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", width: 5, quantum: 8}, {name: "base32hex", alphabet: "0123456789ABCDEFGHIJKLMNOPQRSTUV", width: 5, quantum: 8}}
	for k := range a {
		for j := range a[k].values {
			a[k].values[j] = -1
		}
		for j, c := range []byte(a[k].alphabet) {
			a[k].values[c] = int16(j)
			if k == 0 || k >= 3 {
				if c >= 'a' && c <= 'z' {
					a[k].values[c-32] = int16(j)
				}
				if c >= 'A' && c <= 'Z' {
					a[k].values[c+32] = int16(j)
				}
			}
		}
	}
	return a
}()

// RFC 4648's alphabet union is derived from the same value tables used by
// decoding. A byte outside it contributes to none of the projections.
var reassemblyAlphabet = func() (members [256]bool) {
	for _, codec := range reassemblyCodecs {
		for value, decoded := range codec.values {
			if decoded >= 0 {
				members[value] = true
			}
		}
	}
	return members
}()

type (
	reassemblyNeedle struct{ pattern, length, delta, kind int }
	reassemblyACNode struct {
		next [64]uint32
		fail uint32
		out  []reassemblyNeedle
	}
	reassemblyAC struct {
		nodes []reassemblyACNode
		codec int
	}
)

func (a *reassemblyAC) add(value []byte, n reassemblyNeedle) {
	state := uint32(0)
	for _, c := range value {
		v := reassemblyCodecs[a.codec].values[c]
		if v < 0 {
			panic("nonalphabet core")
		}
		next := a.nodes[state].next[v]
		if next == 0 {
			if len(a.nodes) > math.MaxInt32 {
				panic("literal automaton exceeds address space")
			}
			next = uint32(len(a.nodes) & math.MaxInt32)
			a.nodes = append(a.nodes, reassemblyACNode{})
			a.nodes[state].next[v] = next
		}
		state = next
	}
	n.length = len(value)
	for _, old := range a.nodes[state].out {
		if old == n {
			return
		}
	}
	a.nodes[state].out = append(a.nodes[state].out, n)
}

func (a *reassemblyAC) build() {
	var q []uint32
	for _, n := range a.nodes[0].next {
		if n != 0 {
			q = append(q, n)
		}
	}
	for h := 0; h < len(q); h++ {
		s := q[h]
		for c := 0; c < 1<<reassemblyCodecs[a.codec].width; c++ {
			n := a.nodes[s].next[c]
			if n == 0 {
				a.nodes[s].next[c] = a.nodes[a.nodes[s].fail].next[c]
				continue
			}
			f := a.nodes[a.nodes[s].fail].next[c]
			a.nodes[n].fail = f
			a.nodes[n].out = append(a.nodes[n].out, a.nodes[f].out...)
			q = append(q, n)
		}
	}
}

func reassemblyRequired(tree *syntax.Regexp) []string {
	switch tree.Op {
	case syntax.OpLiteral:
		return []string{string(tree.Rune)}
	case syntax.OpCharClass:
		values, ok := smallCharClassAlternatives(tree.Rune)
		if ok {
			return values
		}
		return nil
	case syntax.OpCapture, syntax.OpPlus:
		return reassemblyRequired(tree.Sub[0])
	case syntax.OpRepeat:
		if tree.Min > 0 {
			return reassemblyRequired(tree.Sub[0])
		}
	case syntax.OpConcat:
		var best []string
		for _, sub := range tree.Sub {
			if v := reassemblyRequired(sub); betterAnchorSet(v, best) {
				best = v
			}
		}
		return best
	case syntax.OpAlternate:
		var result []string
		for _, sub := range tree.Sub {
			v := reassemblyRequired(sub)
			if len(v) == 0 {
				return nil
			}
			result = append(result, v...)
		}
		return result
	}
	return nil
}

func reassemblyVariants(value string) []string {
	runes := []rune(value)
	runes = runes[:min(4, len(runes))]
	out := []string{""}
	for _, r := range runes {
		next := make([]string, 0, len(out)*3)
		for _, s := range out {
			next = append(next, s+string(r))
			for v := unicode.SimpleFold(r); v != r; v = unicode.SimpleFold(v) {
				next = append(next, s+string(v))
			}
		}
		out = next
	}
	return out
}

func reassemblyCore(value string, codec, pad int) ([]byte, int) {
	c := &reassemblyCodecs[codec]
	data := append(make([]byte, pad), []byte(value)...)
	var acc uint32
	nb := 0
	var symbols []byte
	for _, b := range data {
		acc = acc<<8 | uint32(b)
		nb += 8
		for nb >= c.width {
			nb -= c.width
			symbols = append(symbols, c.alphabet[(acc>>uint(nb))&uint32((1<<c.width)-1)])
		}
	}
	left := (pad*8 + c.width - 1) / c.width
	right := (pad + len(value)) * 8 / c.width
	if right <= left {
		return nil, 0
	}
	return symbols[left:right], left*c.width - pad*8
}

type reassemblyRef struct {
	raw  int
	skip uint8
}

type reassemblyPlan struct {
	patterns  []*compiledPattern
	required  [][]string
	assembled *assembledPlan
}

func newReassemblyPlan(patterns []*compiledPattern) (*reassemblyPlan, error) {
	p := &reassemblyPlan{patterns: patterns}
	for _, pattern := range patterns {
		tree, err := syntax.Parse(strings.TrimPrefix(pattern.re.String(), "(?i)"), syntax.Perl)
		if err != nil {
			return nil, fmt.Errorf("parse required literals: %w", err)
		}
		literals := reassemblyCueAnchors(tree)
		if leading, _ := leadingLiteralAnchors(tree); betterAnchorSet(leading, literals) {
			literals = leading
		}
		p.required = append(p.required, literals)
	}
	var err error
	p.assembled, err = newAssembledPlan(p)
	if err != nil {
		return nil, fmt.Errorf("compile reassembly plan: %w", err)
	}
	return p, nil
}
