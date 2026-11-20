// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/binary"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
)

// WithOutboundInjectionWork shares bounded matcher work among the outbound
// injection scans of a single body. Callers should discard the context after
// scanning the body. Positive matches and policy decisions are never reused.
func WithOutboundInjectionWork(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, outboundMatchWorkKey{}, &outboundMatchWork{})
}

type outboundMatchWorkKey struct{}

type outboundMatchWork struct {
	mu       sync.Mutex
	programs map[*regexp.Regexp]*outboundRegexp
	lines    map[string]string
	used     int
}

func (w *outboundMatchWork) matcher(ctx context.Context) func(*compiledPattern, string) []ResponseMatch {
	return func(pattern *compiledPattern, text string) []ResponseMatch {
		if ctx.Err() != nil {
			return nil
		}
		if len(text) >= outboundMatchMinView && strings.Contains(text, "\n") &&
			pattern.responseMemoRegexp != nil && pattern.responseMemoRegexp == pattern.re &&
			!hasExternalTransferCompanions(pattern) {
			if proof := w.regex(pattern.re); proof != nil && proof.provesEmpty(ctx, text) {
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}
		}
		return matchResponsePattern(pattern, text)
	}
}

const (
	outboundMatchMinView = 20_000
	outboundMatchBytes   = 16 << 20
	outboundStateBytes   = 256 << 10
	outboundMaxRuneSteps = 8192
	outboundMaxLineSteps = 12000
	outboundMaxProgram   = 4096
)

// Storage charges include keys, values, backing slices and map overhead.
// Cache exhaustion only prevents retention. It never proves a match absent.
func (w *outboundMatchWork) charge(size int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if size > outboundMatchBytes-w.used {
		return false
	}
	w.used += size
	return true
}

func (w *outboundMatchWork) retainLine(text string, cost int) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	line, exists := w.lines[text]
	if !exists {
		cost += len(text) + 64
	}
	if cost > outboundMatchBytes-w.used {
		return "", false
	}
	w.used += cost
	if !exists {
		if w.lines == nil {
			w.lines = make(map[string]string)
		}
		line = strings.Clone(text)
		w.lines[line] = line
	}
	return line, true
}

func (w *outboundMatchWork) regex(re *regexp.Regexp) *outboundRegexp {
	w.mu.Lock()
	defer w.mu.Unlock()
	if program, exists := w.programs[re]; exists {
		return program
	}
	if outboundMatchBytes-w.used < 1024 {
		return nil
	}
	tree, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil
	}
	prog, err := syntax.Compile(tree.Simplify())
	if err != nil || len(prog.Inst) > outboundMaxProgram {
		return nil
	}
	// Include the program, rune tables and fixed scratch vectors.
	cost := 1024 + cap(prog.Inst)*80
	for _, inst := range prog.Inst {
		cost += cap(inst.Rune) * 4
	}
	if cost > outboundMatchBytes-w.used {
		return nil
	}
	w.used += cost
	if w.programs == nil {
		w.programs = make(map[*regexp.Regexp]*outboundRegexp)
	}
	p := &outboundRegexp{
		owner: w, prog: prog, states: [][]uint32{nil},
		stateIDs: make(map[string]int), steps: make(map[outboundRuneKey]outboundRegexpState),
		lineSteps: make(map[outboundLineKey]outboundRegexpState), marks: make([]uint32, len(prog.Inst)),
	}
	w.programs[re] = p
	return p
}

// outboundRegexp implements an existence check on the same syntax program
// used by Go's regexp. A possible match or an inconclusive check uses Go's
// matcher for selection and locations. Each frontier contains instructions
// reached after consuming the preceding rune, before its lookahead assertions.
type outboundRegexp struct {
	mu         sync.Mutex
	owner      *outboundMatchWork
	prog       *syntax.Prog
	states     [][]uint32
	stateIDs   map[string]int
	steps      map[outboundRuneKey]outboundRegexpState
	lineSteps  map[outboundLineKey]outboundRegexpState
	stateBytes int
	marks      []uint32
	generation uint32
	stack      []uint32
	outputs    []uint32
}

type outboundRuneKey struct {
	id             int
	previous, next rune
}

type outboundLineKey struct {
	id             int
	previous       rune
	line, frontier string
}

type outboundRegexpState struct {
	id       int
	previous rune
	frontier []uint32
	possible bool
}

// EmptyOpContext distinguishes only text edges, newlines and ASCII word
// boundaries. The current rune itself must still be matched exactly.
func outboundPreviousClass(r rune) rune {
	if r < 0 || r == '\n' {
		return r
	}
	if syntax.IsWordChar(r) {
		return 'a'
	}
	return ' '
}

func (p *outboundRegexp) advance(state outboundRegexpState, next rune) outboundRegexpState {
	key := outboundRuneKey{state.id, state.previous, next}
	if state.frontier == nil {
		if result, exists := p.steps[key]; exists {
			return result
		}
	}
	p.generation++
	if p.generation == 0 {
		clear(p.marks)
		p.generation++
	}
	frontier := state.frontier
	if frontier == nil {
		frontier = p.states[state.id]
	}
	// Start at every position so the check includes unanchored matches.
	p.stack = append(p.stack[:0], frontier...)
	// The start index addresses the instruction slice capped at compilation.
	p.stack = append(p.stack, uint32(p.prog.Start)) // #nosec G115 -- start is a validated instruction index.
	p.outputs = p.outputs[:0]
	assertions := syntax.EmptyOpContext(state.previous, next)
	result := outboundRegexpState{previous: outboundPreviousClass(next)}
	for len(p.stack) > 0 {
		pc := p.stack[len(p.stack)-1]
		p.stack = p.stack[:len(p.stack)-1]
		if p.marks[pc] == p.generation {
			continue
		}
		p.marks[pc] = p.generation
		inst := &p.prog.Inst[pc]
		switch inst.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			p.stack = append(p.stack, inst.Out, inst.Arg)
		case syntax.InstCapture, syntax.InstNop:
			p.stack = append(p.stack, inst.Out)
		case syntax.InstEmptyWidth:
			if uint32(assertions)&inst.Arg == inst.Arg {
				p.stack = append(p.stack, inst.Out)
			}
		case syntax.InstRune, syntax.InstRune1:
			if next >= 0 && inst.MatchRune(next) {
				p.outputs = append(p.outputs, inst.Out)
			}
		case syntax.InstRuneAny:
			if next >= 0 {
				p.outputs = append(p.outputs, inst.Out)
			}
		case syntax.InstRuneAnyNotNL:
			if next >= 0 && next != '\n' {
				p.outputs = append(p.outputs, inst.Out)
			}
		case syntax.InstFail:
		default:
			result.possible = true
			return result
		}
	}
	if len(p.outputs) > 0 {
		if state.frontier == nil && p.stateBytes < outboundStateBytes {
			id := p.internState()
			if id != 0 {
				result.id = id
			} else {
				result.frontier = append(state.frontier[:0], p.outputs...)
			}
		} else {
			result.frontier = append(state.frontier[:0], p.outputs...)
		}
	}
	if state.frontier == nil && result.frontier == nil && len(p.steps) < outboundMaxRuneSteps && p.owner.charge(80) {
		p.steps[key] = result
	}
	return result
}

func (p *outboundRegexp) internState() int {
	key := outboundFrontierKey(p.outputs)
	if id, exists := p.stateIDs[key]; exists {
		return id
	}
	cost := len(key)*2 + 64
	if cost > outboundStateBytes-p.stateBytes || !p.owner.charge(cost) {
		p.stateBytes = outboundStateBytes
		return 0
	}
	id := len(p.states)
	p.stateBytes += cost
	p.stateIDs[key] = id
	p.states = append(p.states, slices.Clone(slices.Compact(p.outputs)))
	return id
}

func outboundFrontierKey(frontier []uint32) string {
	slices.Sort(frontier)
	encoded := make([]byte, 0, len(frontier)*4)
	for i, pc := range frontier {
		if i == 0 || pc != frontier[i-1] {
			encoded = binary.LittleEndian.AppendUint32(encoded, pc)
		}
	}
	return string(encoded)
}

func (p *outboundRegexp) provesEmpty(ctx context.Context, text string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := outboundRegexpState{previous: -1}
	for line := range strings.SplitAfterSeq(text, "\n") {
		if ctx.Err() != nil {
			return false
		}
		key := outboundLineKey{id: state.id, previous: state.previous, line: line}
		if state.frontier != nil {
			key.frontier = outboundFrontierKey(state.frontier)
			if cached, exists := p.stateIDs[key.frontier]; exists {
				state.id, state.frontier = cached, nil
				key.id, key.frontier = cached, ""
			}
		}
		if cached, exists := p.lineSteps[key]; exists {
			state = cached
			state.frontier = slices.Clone(cached.frontier)
			continue
		}
		nextCheck := responseBodyContextCheckBytes
		for offset, next := range line {
			if offset >= nextCheck {
				if ctx.Err() != nil {
					return false
				}
				nextCheck = offset + responseBodyContextCheckBytes
			}
			state = p.advance(state, next)
			if state.possible {
				return false
			}
		}
		if len(p.lineSteps) < outboundMaxLineSteps {
			if saved, ok := p.owner.retainLine(line, len(key.frontier)+len(state.frontier)*4+112); ok {
				key.line = saved
				cached := state
				cached.frontier = slices.Clone(state.frontier)
				p.lineSteps[key] = cached
			}
		}
	}
	return ctx.Err() == nil && !p.advance(state, -1).possible
}
