// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "sort"

// Coordinates are decoded-byte offsets in one RFC 4648 codec and phase of
// an exact source view. Sorted disjoint intervals retain holes, so confirming
// a later window cannot pay for an unvisited earlier window.
type (
	assembledInterval struct{ start, end int }
	assembledCharges  struct{ lanes [5][8][]assembledInterval }
)

func (b *assembledBudget) chargesFor(text string) *assembledCharges {
	if b.charged == nil {
		b.charged = make(map[string]*assembledCharges)
	}
	if c := b.charged[text]; c != nil {
		return c
	}
	c := new(assembledCharges)
	b.charged[text] = c
	return c
}

func (b *assembledBudget) charge(c *assembledCharges, codec, phase, offset int) bool {
	if c == nil {
		// A caller without a source registry still pays for each decoded byte.
		if b.used >= maxDecodeTotalBytes {
			b.incomplete = true
			return false
		}
		b.used++
		return true
	}
	lane := &c.lanes[codec][phase]
	// Complete lanes advance sequentially. Extending the last interval needs
	// no search or merge; holes and revisits keep the general interval path.
	if n := len(*lane); n > 0 && (*lane)[n-1].end == offset {
		if b.used >= maxDecodeTotalBytes {
			b.incomplete = true
			return false
		}
		b.used++
		(*lane)[n-1].end++
		return true
	}

	i := sort.Search(len(*lane), func(i int) bool { return (*lane)[i].end >= offset })
	if i < len(*lane) && (*lane)[i].start <= offset && offset < (*lane)[i].end {
		return true
	}
	if b.used >= maxDecodeTotalBytes {
		b.incomplete = true
		return false
	}
	b.used++
	if i < len(*lane) && (*lane)[i].end == offset {
		(*lane)[i].end++
		if i+1 < len(*lane) && (*lane)[i+1].start == offset+1 {
			(*lane)[i].end = (*lane)[i+1].end
			*lane = append((*lane)[:i+1], (*lane)[i+2:]...)
		}
	} else if i < len(*lane) && (*lane)[i].start == offset+1 {
		(*lane)[i].start--
	} else {
		*lane = append(*lane, assembledInterval{})
		copy((*lane)[i+1:], (*lane)[i:])
		(*lane)[i] = assembledInterval{offset, offset + 1}
	}
	return true
}
