// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "sort"

// Coordinates are decoded-byte offsets in one RFC 4648 codec and phase of
// an exact source view. Sorted disjoint intervals retain holes, so confirming
// a later window cannot pay for an unvisited earlier window.
// One text scan owns one terminal allowance across all of its typed views.
type assembledAllowance struct {
	used     int
	charged  map[string]*assembledCharges
	registry *assembledChargeRegistry
}

type (
	assembledInterval struct{ start, end int }
	assembledCharges  struct {
		lanes     [5][8][]assembledInterval
		canonical [5]*assembledCharges
	}
	assembledChargeKey struct {
		projection assembledProjection
		codec      int
	}
	assembledChargeEntry struct {
		source  string
		replay  *assembledPayload
		charges *assembledCharges
	}
	assembledChargeRegistry struct {
		entries map[assembledChargeKey][]assembledChargeEntry
		size    int
		replays map[*assembledPayload]*assembledCharges
	}
)

func (b *assembledBudget) chargesFor(text string) *assembledCharges {
	var replay *assembledPayload
	if b.memo != nil {
		replay = b.memo.replayPayload(text)
	}
	if b.registry == nil {
		b.registry = &assembledChargeRegistry{entries: make(map[assembledChargeKey][]assembledChargeEntry)}
	}
	if replay != nil {
		if c := b.registry.replays[replay]; c != nil {
			return c
		}
	}
	if b.charged == nil {
		b.charged = make(map[string]*assembledCharges)
	}
	if c := b.charged[text]; replay == nil && c != nil {
		return c
	}
	if len(b.charged)+len(b.registry.replays) >= maxDecodeCandidates {
		return nil
	}
	c := new(assembledCharges)
	for codec, projection := range assembledFingerprint(text) {
		key := assembledChargeKey{projection, codec}
		for _, entry := range b.registry.entries[key] {
			source := entry.source
			if entry.replay != nil {
				var ok bool
				source, ok = entry.replay.inspectionText()
				if !ok {
					b.incomplete = true
					if b.memo != nil {
						b.memo.markIncomplete()
						b.memo.reassemblyIncomplete = true
					}
					continue
				}
			}
			if assembledSameProjection(text, source, codec) {
				c.canonical[codec] = entry.charges
				break
			}
		}
		if c.canonical[codec] == nil && b.registry.size < maxDecodeCandidates {
			entry := assembledChargeEntry{source: text, replay: replay, charges: c}
			if replay != nil {
				entry.source = ""
			}
			b.registry.entries[key] = append(b.registry.entries[key], entry)
			b.registry.size++
		}
	}
	if replay == nil {
		b.charged[text] = c
	} else {
		if b.registry.replays == nil {
			b.registry.replays = make(map[*assembledPayload]*assembledCharges)
		}
		b.registry.replays[replay] = c
	}
	return c
}

// canceled reports a caller context that has already ended. The terminal
// stops scheduling more replay; the scan result stays incomplete.
func (b *assembledBudget) canceled() bool {
	if b == nil || b.memo == nil || b.memo.scanCtx == nil || b.memo.scanCtx.Err() == nil {
		return false
	}
	b.incomplete = true
	b.memo.reassemblyIncomplete = true
	return true
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
	if canonical := c.canonical[codec]; canonical != nil {
		c = canonical
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
