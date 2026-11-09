// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyDecodedRetentionUsesReplay(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Marker", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	memo := &decodingMemo{reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true}
	defer memo.releaseProjection()
	roots := make(map[string]bool)
	inputBytes := 0
	for i := range 1000 {
		body := strings.Repeat("78", 2400) + fmt.Sprintf("%08x", i)
		roots[body] = true
		inputBytes += len(body)
		memo.decode(body, true)
	}
	decodedBytes := terminalRetainedBytes(memo, roots)
	if decodedBytes > maxDecodeTotalBytes || memo.retainedBytes > maxDecodeTotalBytes || memo.reassemblyReplayPayloadCount == 0 {
		t.Fatalf("payload ownership exceeded its cap: decoded=%d memo=%d replay=%d", decodedBytes, memo.retainedBytes, memo.reassemblyReplayPayloadCount)
	}
	for _, bucket := range memo.reassemblyReplayPayloads {
		for _, payload := range bucket {
			if payload.current != "" || payload.literal != "" {
				t.Fatal("replay record retained a decoded payload")
			}
		}
	}
	t.Logf("input=%d memo=%d terminal_decoded=%d replay_views=%d cap=%d", inputBytes, memo.retainedBytes, decodedBytes, memo.reassemblyReplayPayloadCount, maxDecodeTotalBytes)
	// Only the decoded outer-base64 view exposes the long separated run.
	// Cache exhaustion must neither skip it nor introduce a new refusal.
	inner := strings.Repeat("a!", 4200) + reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
	encoded := base64.StdEncoding.EncodeToString([]byte(inner))
	roots[encoded] = true
	memo.decode(encoded, true)
	result := finishAssembled(TextDLPResult{Clean: true}, memo)
	if result.Clean || HasInspectionLimit(result.Matches) || !slices.Contains(matchNames(result.Matches), "Marker") {
		t.Fatal("replayed terminal lost coverage or refused at a cache bound", result)
	}
	if retained := terminalRetainedBytes(memo, roots); retained > maxDecodeTotalBytes || memo.retainedBytes > maxDecodeTotalBytes {
		t.Fatalf("finalization retained unbudgeted payloads: terminal=%d memo=%d", retained, memo.retainedBytes)
	}
	for _, bucket := range memo.reassemblyReplayPayloads {
		for _, payload := range bucket {
			if payload.current != "" || payload.decode != nil && payload.decode.current != nil {
				t.Fatal("decoder borrow survived finalization")
			}
		}
	}
}

func TestReassemblyReplayFailuresFailClosed(t *testing.T) {
	p := reassemblyMarkerPlan(t)
	text := reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
	for _, operation := range []assembledPayloadOperation{assembledPayloadSegment, assembledPayloadOperation(255)} {
		memo := &decodingMemo{reassemblyPlan: p, reassemblyDeferred: true}
		payload := &assembledPayload{parent: &assembledPayload{literal: text}, operation: operation, start: -1}
		memo.addReplayPayload(text, payload)
		// Borrow valid bytes only during observation. Corrupt recipe metadata must
		// cause the ordinary outbound inspection-limit refusal at finalization.
		payload.current = text
		memo.reassemblyObserve(text)
		payload.current = ""
		result := finishAssembled(TextDLPResult{Clean: true}, memo)
		if result.Clean || !HasInspectionLimit(result.Matches) {
			t.Fatal("unreplayable work silently skipped", result)
		}
		memo.releaseProjection()
	}
}

func TestReassemblyReplayTransformsAtCacheLimit(t *testing.T) {
	p := reassemblyMarkerPlan(t)
	wire := reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
	for _, tc := range []struct {
		input     string
		operation assembledPayloadOperation
		transform func(string) string
	}{
		{"  " + wire, assembledPayloadWhitespace, compactTextDLPWhitespace},
		{"&amp;" + wire, assembledPayloadHTML, func(s string) string { out, _ := decodeHTMLEntitiesChecked(s); return out }},
	} {
		memo := &decodingMemo{reassemblyPlan: p, reassemblyDeferred: true, retainedBytes: maxDecodeTotalBytes}
		text := tc.transform(tc.input)
		memo.rememberGraphTransform(tc.input, text, tc.operation)
		memo.reassemblyDerive(tc.input, text)
		memo.reassemblyObserve(text)
		if len(memo.reassemblyPendingReplay) == 0 {
			t.Fatal("unbudgeted transform retained payload")
		}
		result := finishAssembled(TextDLPResult{Clean: true}, memo)
		if result.Clean || HasInspectionLimit(result.Matches) {
			t.Fatal("transform replay changed coverage", result)
		}
		for _, bucket := range memo.reassemblyReplayPayloads {
			for _, payload := range bucket {
				if payload.current != "" || payload.decode != nil && payload.decode.current != nil {
					t.Fatal("borrow outlived inspection")
				}
			}
		}
		memo.releaseProjection()
	}
}

func terminalRetainedBytes(m *decodingMemo, roots map[string]bool) int {
	owned := make(map[string]bool)
	for _, text := range m.reassemblyPending {
		owned[text] = true
	}
	for text := range m.reassemblySeen {
		owned[text] = true
	}
	for text := range m.reassemblyViewKinds {
		owned[text] = true
	}
	for text := range m.reassemblyTextRoots {
		owned[text] = true
	}
	for text, parent := range m.reassemblyParents {
		owned[text], owned[parent] = true, true
	}
	for text := range m.assembledCharged {
		owned[text] = true
	}
	if m.assembledChargeRegistry != nil {
		for _, entries := range m.assembledChargeRegistry.entries {
			for _, entry := range entries {
				owned[entry.source] = true
			}
		}
	}
	seen := make(map[*assembledPayload]bool)
	var visit func(*assembledPayload)
	visit = func(payload *assembledPayload) {
		if payload == nil || seen[payload] {
			return
		}
		seen[payload] = true
		owned[payload.literal], owned[payload.current] = true, true
		visit(payload.parent)
		visit(payload.contextParent)
		if payload.decode != nil {
			visit(payload.decode.source)
			for _, view := range payload.decode.current {
				owned[view.text] = true
			}
		}
	}
	for _, bucket := range m.reassemblyReplayPayloads {
		for _, payload := range bucket {
			visit(payload)
		}
	}
	for _, payload := range m.reassemblyReplayParents {
		visit(payload)
	}
	decodedBytes := 0
	for text := range owned {
		if !roots[text] {
			decodedBytes += len(text)
		}
	}
	return decodedBytes
}

func TestReassemblyReplayPreservesKeywordDecisions(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Labeled marker", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh, Keywords: []string{"lookup"}}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, label := range []string{"lookup", "ordinary"} {
		inner := strings.Repeat("a!", 4200) + reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte(" "+label+" MARK1234 ")))
		body := base64.StdEncoding.EncodeToString([]byte(inner))
		for _, inbound := range []bool{false, true} {
			for _, shared := range []bool{false, true} {
				var want TextDLPResult
				for _, full := range []bool{false, true} {
					ctx, release := WithSharedDecodes(t.Context())
					memo := &decodingMemo{reassemblyDeferred: true, inbound: inbound, reassemblyInbound: inbound}
					if shared {
						memo.shared = sharedDecodesFrom(ctx)
					}
					if full {
						if shared {
							memo.shared.store.retainedBytes = maxDecodeTotalBytes
						} else {
							memo.retainedBytes = maxDecodeTotalBytes
						}
					}
					got := sc.scanTextForDLPWithDecodes(ctx, body, textDLPOptions{scanSecretLeak: !inbound}, memo)
					got = finishAssembled(got, memo)
					memo.releaseProjection()
					release()
					if !full {
						want = got
					} else if !reflect.DeepEqual(got, want) {
						t.Fatalf("cache exhaustion changed keyword result (label=%s inbound=%v shared=%v): got %+v want %+v", label, inbound, shared, got, want)
					}
					if got.Clean != (label != "lookup") || HasInspectionLimit(got.Matches) {
						t.Fatalf("invalid keyword witness: label=%s inbound=%v shared=%v result=%+v", label, inbound, shared, got)
					}
				}
			}
		}
	}
}

func TestReassemblySegmentReplayBorrowEndsWithWalk(t *testing.T) {
	p := reassemblyMarkerPlan(t)
	memo := &decodingMemo{reassemblyPlan: p, reassemblyDeferred: true, retainedBytes: maxDecodeTotalBytes}
	defer memo.releaseProjection()
	encoded := reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
	raw := " " + encoded + "/ordinary "
	memo.reassemblyObserve(raw)
	compacted, _ := memo.compactWhitespace(raw)
	source := memo.reassemblySegmentSource(compacted)
	if source.replay == nil || source.replay.current != compacted {
		t.Fatal("walk did not borrow its caller-owned source")
	}
	for range 2 {
		source.observe(encoded)
		memo.decode(encoded, true)
	}
	source.release()
	if source.replay.current != "" {
		t.Fatal("walk retained its borrowed payload")
	}
	result := finishAssembled(TextDLPResult{Clean: true}, memo)
	if result.Clean || HasInspectionLimit(result.Matches) {
		t.Fatal("released segment recipe lost detection", result)
	}
}

// Replaying sibling views of one decoder must share a single walk of the
// source, and holding a second decoder must release the first so retention
// stays at one source's views.
func TestReassemblyRecipeReplayHoldsOneDecode(t *testing.T) {
	first := base64.StdEncoding.EncodeToString([]byte("MARK1234 first replayed source"))
	second := base64.StdEncoding.EncodeToString([]byte("MARK5678 second replayed source"))
	cache := new(assembledRecipeCache)
	recipe := func(text string) (*assembledDecodeRecipe, []decodedResult) {
		views, _ := decodeEncodingsBudgetMode(text, false, 0, false)
		if len(views) == 0 {
			t.Fatalf("fixture %q produced no decoded views", text)
		}
		return &assembledDecodeRecipe{source: &assembledPayload{literal: text}, cache: cache}, views
	}
	r1, v1 := recipe(first)
	r2, v2 := recipe(second)

	a := &assembledPayload{decode: r1, ordinal: 0}
	if got, ok := a.materialize(); !ok || got != v1[0].text {
		t.Fatalf("first replay = %q, %v; want %q", got, ok, v1[0].text)
	}
	if r1.current == nil || cache.active != r1 {
		t.Fatal("replayed decode was not held for sibling lookups")
	}
	held := &r1.current[0]
	if _, ok := a.materialize(); !ok || &r1.current[0] != held {
		t.Fatal("sibling lookup walked the source again")
	}

	b := &assembledPayload{decode: r2, ordinal: 0}
	if got, ok := b.materialize(); !ok || got != v2[0].text {
		t.Fatalf("second replay = %q, %v; want %q", got, ok, v2[0].text)
	}
	if r1.current != nil || cache.active != r2 {
		t.Fatal("holding a second decode did not release the first")
	}
	if got, ok := a.materialize(); !ok || got != v1[0].text {
		t.Fatalf("replay after release = %q, %v; want %q", got, ok, v1[0].text)
	}

	cache.release()
	if r1.current != nil || r2.current != nil || cache.active != nil {
		t.Fatal("scan release left decoded views held")
	}
	if got, ok := (&assembledPayload{decode: r1, ordinal: len(v1)}).materialize(); ok {
		t.Fatalf("out-of-range ordinal replayed %q", got)
	}
}

// A fingerprint names a bucket, not a text. Two different texts forced into
// one bucket must not resolve to each other's payload, and a registered text
// must resolve to its own payload without rebuilding any bytes.
func TestReassemblyReplayLookupComparesRegisteredDigest(t *testing.T) {
	memo := &decodingMemo{reassemblyPlan: reassemblyMarkerPlan(t), reassemblyDeferred: true}
	registered := strings.Repeat("a", 32)
	other := strings.Repeat("b", 32)
	payload := memo.addReplayPayload(registered, &assembledPayload{literal: registered})
	if payload == nil {
		t.Fatal("registration refused")
	}
	// Force a collision: file the payload under the other text's bucket too.
	memo.reassemblyReplayPayloads[assembledPayloadFingerprint(other)] = []*assembledPayload{payload}
	if got := memo.replayPayload(other); got != nil {
		t.Fatal("fingerprint collision resolved to another text's payload")
	}
	// A payload whose bytes can no longer be rebuilt is still found by its
	// registered digest; replay itself refuses it later.
	payload.literal, payload.parent, payload.operation = "", &assembledPayload{}, assembledPayloadOperation(255)
	if got := memo.replayPayload(registered); got != payload {
		t.Fatal("registered text did not resolve to its payload")
	}
}

// Segments are observed in split order; a later duplicate segment must still
// replay its own bytes, and an out-of-order segment falls back to a full search.
func TestReassemblySegmentObserveForwardCursor(t *testing.T) {
	memo := &decodingMemo{reassemblyPlan: reassemblyMarkerPlan(t), reassemblyDeferred: true}
	text := "alpha/beta/alpha/gamma"
	root := memo.addReplayPayload(text, &assembledPayload{literal: text})
	source := assembledSegmentSource{memo: memo, text: text, replay: root, kind: assembledTextView}
	for i, seg := range []string{"alpha", "beta", "alpha", "gamma", "beta"} {
		source.observe(seg)
		want := []int{5, 10, 16, 22, 10}[i]
		if source.cursor != want {
			t.Fatalf("segment %d cursor=%d want=%d", i, source.cursor, want)
		}
	}
	for _, seg := range []string{"alpha", "beta", "gamma"} {
		payload := memo.replayPayload(seg)
		if payload == nil {
			t.Fatalf("segment %q not registered", seg)
		}
		if got, ok := payload.materialize(); !ok || got != seg {
			t.Fatalf("segment %q replayed %q, %v", seg, got, ok)
		}
	}
	if memo.reassemblyIncomplete {
		t.Fatal("in-text segments marked the scan incomplete")
	}
	source.observe("missing")
	if !memo.reassemblyIncomplete {
		t.Fatal("a segment absent from its source did not fail closed")
	}
}
