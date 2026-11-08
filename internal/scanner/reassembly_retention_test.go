// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"fmt"
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
	if decodedBytes > maxDecodeTotalBytes || memo.retainedBytes > maxDecodeTotalBytes || len(memo.reassemblyPendingReplay) == 0 {
		t.Fatalf("payload ownership exceeded its cap: decoded=%d memo=%d replay=%d", decodedBytes, memo.retainedBytes, len(memo.reassemblyPendingReplay))
	}
	for _, bucket := range memo.reassemblyReplayPayloads {
		for _, payload := range bucket {
			if payload.current != "" || payload.literal != "" {
				t.Fatal("replay record retained a decoded payload")
			}
		}
	}
	t.Logf("input=%d memo=%d terminal_decoded=%d replay_views=%d cap=%d", inputBytes, memo.retainedBytes, decodedBytes, len(memo.reassemblyPendingReplay), maxDecodeTotalBytes)
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
