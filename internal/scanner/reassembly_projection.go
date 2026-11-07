// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"sync"
)

// Fingerprints use the FNV-1a recurrence published by hash/fnv. They are only
// an index: exact projection comparison below is required before reusing work.
type (
	assembledProjection struct {
		hash    uint64
		symbols int
	}
	assembledProjectionEntry struct {
		key     assembledProjection
		view    int
		ready   bool
		codec   uint8
		textual bool
	}
)

func assembledFingerprint(text string) (out [5]assembledProjection) {
	for i := range out {
		out[i].hash = 14695981039346656037
	}
	for at := range len(text) {
		b := text[at]
		if !reassemblyAlphabet[b] {
			continue
		}
		for i := range reassemblyCodecs {
			v := reassemblyCodecs[i].values[b]
			if v >= 0 {
				out[i].hash = (out[i].hash ^ uint64(v)) * 1099511628211
				out[i].symbols++
			}
		}
	}
	return out
}

func assembledSameProjection(a, b string, codec int) bool {
	alphabet := &reassemblyCodecs[codec]
	i, j := 0, 0
	for {
		for i < len(a) && alphabet.values[a[i]] < 0 {
			i++
		}
		for j < len(b) && alphabet.values[b[j]] < 0 {
			j++
		}
		if i == len(a) || j == len(b) {
			return i == len(a) && j == len(b)
		}
		if alphabet.values[a[i]] != alphabet.values[b[j]] {
			return false
		}
		i++
		j++
	}
}

// Equal projections have equal symbol values, phase streams, literal cues,
// decoded bytes and regex/validator decisions. Raw coordinates affect provenance
// only. Hex and base32 fold through the RFC value tables; base64 does not fold.
// A hash collision costs comparison time and never suppresses scanning.
// Linear probing follows the open-addressing construction in CLRS, section
// 11.4. At most maxDecodeCandidates codec entries occupy a half-full table.
// Growth retains no payloads, and its cumulative backing arrays have a fixed
// bound even if garbage collection has not reclaimed any replaced array.
// sync.Pool recycles only cleared storage, as described by Go's sync package.
// A scan retains its owner until all of that scan's terminal consumers finish.
// The array stores integers and fingerprints; it owns no graph payloads.
type assembledProjectionStorage struct{ table []assembledProjectionEntry }

var assembledProjectionPool = sync.Pool{New: func() any { return &assembledProjectionStorage{} }}

func (m *decodingMemo) releaseProjection() {
	if storage := m.assembledProjectionStorage; storage != nil {
		clear(m.assembledProjectionTable)
		storage.table = m.assembledProjectionTable
		m.assembledProjectionTable = nil
		m.assembledProjectionStorage = nil
		assembledProjectionPool.Put(storage)
	}
}

func assembledProjectionSlot(key assembledProjection, codec int, slots int) int {
	// Every table has at most 2*maxDecodeCandidates slots. Masking first
	// bounds the conversion; the final mask selects the current table.
	return (int(key.hash&(2*maxDecodeCandidates-1)) ^ codec) & (slots - 1)
}

func (m *decodingMemo) assembledGrowProjection() {
	if m.assembledProjectionStorage == nil {
		storage, _ := assembledProjectionPool.Get().(*assembledProjectionStorage)
		if storage == nil {
			storage = &assembledProjectionStorage{}
		}
		m.assembledProjectionStorage = storage
		m.assembledProjectionTable = storage.table
	}
	if 2*(m.assembledProjectionEntries+1) <= len(m.assembledProjectionTable) {
		return
	}
	// Sixteen is the first power of two above twice the five RFC alphabets.
	slots := min(2*maxDecodeCandidates, max(16, 2*len(m.assembledProjectionTable)))
	next := make([]assembledProjectionEntry, slots)
	for _, entry := range m.assembledProjectionTable {
		if !entry.ready {
			continue
		}
		at := assembledProjectionSlot(entry.key, int(entry.codec), slots)
		for next[at].ready {
			at = (at + 1) & (slots - 1)
		}
		next[at] = entry
	}
	m.assembledProjectionTable = next
}

func (m *decodingMemo) assembledSkip(view int) uint8 {
	if view < 0 || view >= len(m.reassemblyPending) {
		m.markIncomplete()
		return 31
	}
	// Once full, bypass reuse entirely: the caller inspects the whole view.
	if m.assembledProjectionEntries >= maxDecodeCandidates {
		return 0
	}
	// Keyword eligibility depends on source coordinates, even when RFC
	// projections agree. A different source must check its own windows.
	if m.keywordsActive() {
		return 0
	}
	text := m.reassemblyPending[view]
	fingerprint := assembledFingerprint(text)
	var skip uint8
	for codec, key := range fingerprint {
		first := &m.assembledProjectionFirst[codec]
		matches := func(entry assembledProjectionEntry) bool {
			if entry.view < 0 || entry.view >= len(m.reassemblyPending) {
				m.markIncomplete()
				return false
			}
			if m.reassemblyViewKinds[text].textual() && !entry.textual {
				return false
			}
			return assembledSameProjection(text, m.reassemblyPending[entry.view], codec)
		}
		if first.ready && first.key == key && matches(*first) {
			skip |= 1 << uint(codec)
			continue
		}
		if len(m.assembledProjectionTable) > 0 {
			at := assembledProjectionSlot(key, codec, len(m.assembledProjectionTable))
			for entry := m.assembledProjectionTable[at]; entry.ready; entry = m.assembledProjectionTable[at] {
				if int(entry.codec) == codec && entry.key == key && matches(entry) {
					skip |= 1 << uint(codec)
					break
				}
				at = (at + 1) & (len(m.assembledProjectionTable) - 1)
			}
		}
		if m.incomplete && !m.inbound {
			return 31
		}
		// Exhaustion stops admission only. Every unskipped codec still runs
		// its complete inspection; the reuse index never decides completeness.
		if skip&(1<<uint(codec)) != 0 || m.assembledProjectionEntries >= maxDecodeCandidates {
			continue
		}
		entry := assembledProjectionEntry{key: key, view: view, ready: true, codec: uint8(codec), textual: m.reassemblyViewKinds[text].textual()}
		if !first.ready {
			*first = entry
		} else {
			m.assembledGrowProjection()
			at := assembledProjectionSlot(key, codec, len(m.assembledProjectionTable))
			for m.assembledProjectionTable[at].ready {
				at = (at + 1) & (len(m.assembledProjectionTable) - 1)
			}
			m.assembledProjectionTable[at] = entry
		}
		m.assembledProjectionEntries++
	}
	return skip
}
