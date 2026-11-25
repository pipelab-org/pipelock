// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"math/rand/v2"
	"strings"
	"testing"
)

func TestDecodedMatchChargesGeneratedViewLabels(t *testing.T) {
	key := decodedMatchKey{text: strings.Repeat("x", decodedMatchMinRetain), encoding: encodingHex}
	matches := make([]TextDLPMatch, 1, 2)
	for i := range matches[:cap(matches)] {
		matches[:cap(matches)][i].span = newMatchSpan(0, 1, dlpViewLabel(key.encoding), "marker", "", "")
	}
	want := decodedMatchEntrySize + len(key.encoding) + cap(matches)*textDLPMatchSize
	for _, match := range matches[:cap(matches)] {
		want += len(match.span.ViewLabel)
	}
	var memo decodingMemo
	memo.retainDecodedMatches(key, matches)
	if memo.decodedMatchesBytes != want {
		t.Fatalf("charged %d bytes, want %d including generated view labels", memo.decodedMatchesBytes, want)
	}
	full := decodingMemo{retainedBytes: maxDecodeTotalBytes - want + 1}
	full.retainDecodedMatches(key, matches)
	if len(full.decodedMatches) != 0 {
		t.Fatal("retained generated labels past the retention allowance")
	}
}

// A retained result is charged a fixed entry, not a copy of its candidate,
// so a message-sized view costs the same as a short one.
func TestDecodedMatchResultChargeIsFixed(t *testing.T) {
	short := decodedMatchKey{text: strings.Repeat("a", decodedMatchMinRetain), encoding: encodingBase64}
	long := decodedMatchKey{text: strings.Repeat("b", maxDecodeTotalBytes/2), encoding: encodingBase64}
	var m decodingMemo
	m.retainDecodedMatches(short, nil)
	first := m.decodedMatchesBytes
	m.retainDecodedMatches(long, nil)
	if len(m.decodedMatches) != 2 || m.decodedMatchesBytes != 2*first || first != decodedMatchEntrySize+len(encodingBase64) {
		t.Fatalf("entries %d charged %d after short charge %d", len(m.decodedMatches), m.decodedMatchesBytes, first)
	}
	if m.retainedBytes != m.decodedMatchesBytes {
		t.Fatalf("retained %d, results charged %d", m.retainedBytes, m.decodedMatchesBytes)
	}
}

// The digest key keeps every field of the full key distinct.
func TestDecodedMatchCacheKeyFields(t *testing.T) {
	a, b := &Scanner{}, &Scanner{}
	base := decodedMatchKey{scanner: a, text: "candidate text one", encoding: encodingBase64}
	variants := []decodedMatchKey{
		base,
		{scanner: b, text: base.text, encoding: base.encoding},
		{scanner: a, text: "candidate text two", encoding: base.encoding},
		{scanner: a, text: base.text, encoding: encodingHex},
		{scanner: a, text: base.text, encoding: base.encoding, core: true},
		{scanner: a, text: base.text, encoding: base.encoding, core: true, normalizedCore: true},
		{scanner: a, text: base.text, encoding: base.encoding, cardOnly: true},
		{scanner: a, text: base.text, encoding: base.encoding, cardSource: true},
	}
	seen := make(map[decodedMatchCacheKey]int)
	for i, key := range variants {
		if j, ok := seen[key.cacheKey()]; ok {
			t.Fatalf("variant %d shares a cache key with variant %d", i, j)
		}
		seen[key.cacheKey()] = i
	}
	if base.cacheKey() != (decodedMatchKey{scanner: a, text: strings.Clone(base.text), encoding: base.encoding}).cacheKey() {
		t.Fatal("equal keys produced different cache keys")
	}
}

// Whole-message transforms retained for reassembly cannot take the part of
// the existing allowance reserved for results, and the total stays within it.
func TestDecodedMatchReserveSurvivesFullRetention(t *testing.T) {
	var m decodingMemo
	if !m.reservePayloadBytes(m.generalRetentionRemaining()) || m.reservePayloadBytes(1) {
		t.Fatal("fixture did not exhaust general retention")
	}
	m.retainNormalized("Some Text", "some text")
	m.retainDecode(decodingMemoKey{text: "aGVsbG8="}, []decodedResult{{text: "hello"}}, true)
	if len(m.normalized) != 0 || len(m.views) != 0 {
		t.Fatal("general retention used the result reserve")
	}
	for i := range maxDecodeCandidates {
		m.retainDecodedMatches(decodedMatchKey{text: strings.Repeat("x", decodedMatchMinRetain) + string(rune('a'+i%26)) + strings.Repeat("y", i), encoding: encodingHex}, nil)
	}
	if len(m.decodedMatches) != maxDecodeCandidates {
		t.Fatalf("retained %d results, want the full entry limit %d", len(m.decodedMatches), maxDecodeCandidates)
	}
	if m.retainedBytes > maxDecodeTotalBytes {
		t.Fatalf("retained %d bytes past the %d allowance", m.retainedBytes, maxDecodeTotalBytes)
	}
	if m.generalRetentionRemaining() < 0 || m.reservePayloadBytes(m.generalRetentionRemaining()+1) {
		t.Fatal("result retention let general retention exceed the allowance")
	}
}

// Short candidates may fill only half of the entry limit; long candidates
// may use the rest.
func TestDecodedMatchShortAdmission(t *testing.T) {
	var m decodingMemo
	for i := range maxDecodeCandidates {
		m.retainDecodedMatches(decodedMatchKey{text: "s" + strings.Repeat("z", i%97) + string(rune(0x100+i)), encoding: encodingHex}, nil)
	}
	if len(m.decodedMatches) != maxDecodeCandidates/2 {
		t.Fatalf("short candidates filled %d entries, want %d", len(m.decodedMatches), maxDecodeCandidates/2)
	}
	m.retainDecodedMatches(decodedMatchKey{text: strings.Repeat("L", decodedMatchMinRetain), encoding: encodingHex}, nil)
	if len(m.decodedMatches) != maxDecodeCandidates/2+1 {
		t.Fatal("a long candidate was refused while entries remained")
	}
	var empty decodingMemo
	empty.retainDecodedMatches(decodedMatchKey{encoding: encodingHex}, nil)
	if len(empty.decodedMatches) != 0 {
		t.Fatal("an empty candidate was retained")
	}
}

// Projection digests are equal exactly when the projections are.
func TestAssembledProjectionDigestMatchesComparison(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11)) // #nosec G404 -- reproducible projection corpus.
	const alphabet = "0123456789abcdefABCDEFghijkzGHIJKZ+/-_=: \n.%&\x00\xff"
	random := func() string {
		var b strings.Builder
		for range rng.IntN(40) {
			b.WriteByte(alphabet[rng.IntN(len(alphabet))])
		}
		return b.String()
	}
	fixed := [][2]string{
		{"deadBEEF 0123", "DEAD-beef:0123"},
		{"", "::  .."},
		{"abc", "abcd"},
		{"QUJD", "qujd"},
		{"a\x00b", "ab"},
	}
	pairs := append([][2]string(nil), fixed...)
	for range 4000 {
		a := random()
		b := a
		if rng.IntN(2) == 0 {
			b = random()
		} else if len(b) > 0 {
			bs := []byte(b)
			bs[rng.IntN(len(bs))] = alphabet[rng.IntN(len(alphabet))]
			b = string(bs)
		}
		pairs = append(pairs, [2]string{a, b})
	}
	equalSeen := 0
	for _, pair := range pairs {
		for codec := range reassemblyCodecs {
			same := assembledSameProjection(pair[0], pair[1], codec)
			if digest := assembledProjectionDigest(pair[0], codec) == assembledProjectionDigest(pair[1], codec); digest != same {
				t.Fatalf("codec %d %q vs %q: digest equal %v, projection equal %v", codec, pair[0], pair[1], digest, same)
			}
			if same && pair[0] != pair[1] {
				equalSeen++
			}
		}
	}
	if equalSeen == 0 {
		t.Fatal("fixture never compared distinct texts with equal projections")
	}
}

// A replayed registry entry is compared through the digest of the bytes it
// registered. Equal projections share charges and different ones do not;
// neither comparison re-derives the payload.
func TestChargesForComparesReplayByRegisteredDigest(t *testing.T) {
	const registered, folded, other = "deadBEEF 0123", "DEAD-beef:0123", "cafe 4567"
	// Materializing this payload dereferences a nil source and panics.
	payload := &assembledPayload{decode: &assembledDecodeRecipe{}}
	shared := new(assembledCharges)
	entry := assembledChargeEntry{replay: payload, charges: shared, projection: assembledProjectionDigest(registered, 0)}
	registry := &assembledChargeRegistry{entries: map[assembledChargeKey][]assembledChargeEntry{
		{assembledFingerprint(registered)[0], 0}: {entry},
		{assembledFingerprint(other)[0], 0}:      {entry},
	}}
	budget := assembledBudget{registry: registry}
	if got := budget.chargesFor(folded); got == nil || got.canonical[0] != shared {
		t.Fatal("equal projection did not share the registered charges")
	}
	if got := budget.chargesFor(other); got == nil || got.canonical[0] != nil {
		t.Fatal("different projection shared the registered charges")
	}
	if budget.incomplete {
		t.Fatal("digest comparison marked inspection incomplete")
	}
}
