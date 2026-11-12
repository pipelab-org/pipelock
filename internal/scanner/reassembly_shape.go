// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0
package scanner

import (
	"fmt"
	"math/bits"
	"regexp"
	"regexp/syntax"
	"unicode/utf8"
)

// Each byte lane counts consecutive compatible raw symbols for one phase.
// RFC 4648 packs most-significant bits first. For a symbol segment overlapping
// a byte, compatibility requires that some member supplies exactly those bits.
// Separate byte segments may choose different members, a conservative superset.
// The high bit marks the regex-derived minimum run.
type assembledShape struct {
	id           int
	minimum      int
	window       int
	local        *regexp.Regexp
	validate     *compiledPattern
	validateRule bool
	// glued admits a window whose only candidate has one glued rune before
	// it. The bounded local grammar rejects that candidate; searchLane
	// accepts it, so the screen must not refuse its lane.
	glued    *compiledPattern
	segments [8][9][4]uint64
	members  [256]bool
	masks    [5][8][64]uint64
	bias     [5]uint64
}

const (
	shapeOnes uint64 = 0x0101010101010101
	shapeHigh uint64 = 0x8080808080808080
)

func newAssembledShape(id int, expr string) (*assembledShape, error) {
	tree, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, err
	}
	s := &assembledShape{id: id, minimum: shapeMinLen(tree)}
	// A finite grammar bounds the bytes of any match, including folded runes.
	if n := reassemblyMaxBytes(tree); n > 0 && n <= maxReassembledTokenLen {
		s.window = n
		s.local = regexp.MustCompile(tree.String())
	}
	// Join the existing regex-derived shape analysis. A rune-length lower
	// bound is also a byte-length lower bound, including folded UTF-8 runes.
	gate := analyzeRegexShape(tree)
	if gate == nil {
		for i := range s.members {
			s.members[i] = true
		}
	} else {
		for b := 0; b < 128; b++ {
			s.members[b] = gate.class.has(byte(b))
		}
		// A matched non-ASCII rune contributes its exact UTF-8 bytes. Taking
		// their union is conservative: incompatible byte combinations may
		// admit work, but every genuine rune still satisfies the run screen.
		for _, r := range gate.nonASCII {
			for _, b := range []byte(string(r)) {
				s.members[b] = true
			}
		}
	}
	for offset := range 8 {
		for n := 1; n <= 8-offset; n++ {
			for value, member := range s.members {
				if member {
					segment := (value >> uint(8-offset-n)) & ((1 << uint(n)) - 1)
					s.segments[offset][n][segment/64] |= uint64(1) << uint(segment%64)
				}
			}
		}
	}
	for codec, c := range reassemblyCodecs {
		// Any interval of minimum*8 bits contains at least this many complete
		// symbols. Reserve one additional symbol so a cue's final pair can
		// lie entirely inside the match; partial edge symbols stay optional.
		threshold := s.minimum*8/c.width - 2
		if threshold < 1 {
			return nil, fmt.Errorf("regex has no positive correlated run bound for %s", c.name)
		}
		threshold = min(128, threshold)
		for phase := range c.quantum {
			s.bias[codec] |= uint64(128-threshold) << uint(phase*8)
		}
		for position := range c.quantum {
			for value := 0; value < 1<<c.width; value++ {
				for phase := range c.quantum {
					offset := ((position-phase)*c.width%8 + 8) % 8
					if s.compatible(offset, c.width, value) {
						s.masks[codec][position][value] |= uint64(255) << uint(phase*8)
					}
				}
			}
		}
	}
	return s, nil
}

func shapePhase(hit uint64) int { return bits.TrailingZeros64(hit) / 8 }

// Shapes live with their immutable owning plan, including across reloads.
func getAssembledShape(id int, expr string) (*assembledShape, error) {
	return newAssembledShape(id, expr)
}

// Preserve correlation only at a run cue. The extra complete-symbol margin
// ensures a true interval has a cue whose last two symbols lie inside it.
func (s *assembledShape) pair(codec, phase, symbols int, previous, current int16) bool {
	c := &reassemblyCodecs[codec]
	offset := ((symbols-2-phase)*c.width%8 + 8) % 8
	return s.compatible(offset, 2*c.width, int(previous)<<uint(c.width)|int(current))
}

func (s *assembledShape) compatible(offset, width, value int) bool {
	consumed := 0
	for consumed < width {
		n := min(width-consumed, 8-offset)
		segment := (value >> uint(width-consumed-n)) & ((1 << uint(n)) - 1)
		if s.segments[offset][n][segment/64]&(uint64(1)<<uint(segment%64)) == 0 {
			return false
		}
		consumed += n
		offset = 0
	}
	return true
}

// The symbol screen is a conservative bit projection. Confirm a complete
// class run around its last complete phase byte before admitting a lane. A
// genuine match contains a minimum-length class run and supplies an interior
// paired cue. Both sides of that byte matter when a compatible prefix has
// already advanced the raw counter. The existing normalizer unit bounds local
// work; longer grammars retain a weaker necessary condition, never a refusal.
func (s *assembledShape) run(text string, codec, phase, symbols, end int) bool {
	position := assembledPosition{codec, phase, symbols, end}
	return s.classRun(text, position) && s.grammarNear(text, position)
}

// A cue that confirms a genuine match lies inside it, so its last complete
// byte belongs to the match and every match byte lies within window bytes of
// it. Complete neighboring runes preserve the assertion context of every
// genuine match around that cue. Existence decides admission.
func (s *assembledShape) grammarNear(text string, position assembledPosition) bool {
	if s.local == nil {
		return true
	}
	// utf8.UTFMax supplies complete neighboring runes for empty-width
	// assertions. Every match byte lies within window of the interior cue;
	// anchored genuine matches also include their actual lane edge.
	window := s.window + utf8.UTFMax
	ref := assembledOrigin(text, position, window)
	data := make([]byte, 0, 2*window)
	assembledReplay(text, position.codec, ref.raw, len(text), ref.skip, func(b byte, _ int) bool {
		data = append(data, b)
		return len(data) < cap(data)
	})
	var ok bool
	if s.validate != nil {
		_, _, ok = s.validate.firstAcceptedSpan(string(data), nil)
	} else {
		ok = s.local.Match(data)
	}
	return ok || s.gluedNear(string(data))
}

func (s *assembledShape) gluedNear(view string) bool {
	if s.glued == nil {
		return false
	}
	for _, loc := range s.glued.providerCandidateSpans(view) {
		if _, _, ok := s.glued.gluedCandidateSpan(view, loc); ok {
			return true
		}
	}
	return false
}

func (s *assembledShape) classRun(text string, position assembledPosition) bool {
	codec := position.codec
	required := min(s.minimum, maxReassembledTokenLen)
	ref := assembledOrigin(text, position, required)
	consecutive := 0
	assembledReplay(text, codec, ref.raw, position.end, ref.skip, func(b byte, _ int) bool {
		if s.members[b] {
			consecutive++
		} else {
			consecutive = 0
		}
		return true
	})
	if consecutive == 0 {
		return false
	}
	if consecutive >= required {
		return true
	}
	// Start at the next complete phase byte, preserving pending symbol bits.
	ref = assembledOrigin(text, position, 0)
	cursor := assembledForwardCursor{text: text, codec: codec, raw: ref.raw, skip: int(ref.skip)}
	for consecutive < required {
		b, ok := cursor.nextByte()
		if !ok || !s.members[b] {
			return false
		}
		consecutive++
	}
	return true
}
