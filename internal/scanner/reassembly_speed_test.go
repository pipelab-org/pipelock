// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblySymbolAdmission(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Marker", re: regexp.MustCompile(`ABC[0-9]{4}`)}})
	if err != nil {
		t.Fatal(err)
	}
	wire := base64.RawStdEncoding.EncodeToString([]byte("ABC1234"))
	minimum := p.assembled.nestedMinimum
	if len(wire) != minimum {
		t.Fatal("witness is not exactly at the derived bound", len(wire), minimum)
	}
	for _, tc := range []struct {
		name, input string
		want        bool
	}{
		{"below", strings.Repeat("!", maxReassembledTokenLen) + reassemblyBang(wire[:len(wire)-1]), false},
		{"at", reassemblyBang(wire), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if assembledEnoughSymbols(tc.input, minimum) != tc.want {
				t.Fatal("incorrect necessary symbol bound")
			}
			// Run the unscreened terminal independently to prove the rejected
			// input really cannot produce a finding, not merely that it skips.
			raw := reassemblyTerminal(p, tc.input, &assembledBudget{})
			if (len(raw.findings) > 0) != tc.want || raw.incomplete {
				t.Fatal("unscreened control", raw)
			}
			memo := &decodingMemo{reassemblyPlan: p, reassemblyDeferred: true}
			defer memo.releaseProjection()
			memo.reassemblyObserve(tc.input)
			if (len(memo.reassemblyPending) > 0) != tc.want {
				t.Fatal("unexpected terminal registration")
			}
			got := finishAssembled(TextDLPResult{Clean: true}, memo)
			if (len(got.Matches) > 0) != tc.want || got.Incomplete || HasInspectionLimit(got.Matches) {
				t.Fatal("screened control", got)
			}
		})
	}
	if !assembledEnoughSymbols("", 0) || !assembledEnoughSymbols("", -1) {
		t.Fatal("unknown bound refused work")
	}
}

func TestReassemblyEmptyTerminalReuse(t *testing.T) {
	p := reassemblyMarkerPlan(t)
	plain := "ordinary report about the requested service status"
	key := assembledEmptyKey{p, plain, textDLPAllPatterns, false}
	for round := range 2 {
		memo := &decodingMemo{reassemblyPlan: p, reassemblyDeferred: true}
		memo.reassemblyObserve(plain)
		if round == 1 && len(memo.reassemblyPending) != 0 {
			t.Fatal("proved empty terminal was registered again")
		}
		got := finishAssembled(TextDLPResult{Clean: true}, memo)
		memo.releaseProjection()
		if !got.Clean || len(got.Matches) != 0 || !p.emptyTerminal(key, false) {
			t.Fatal("empty proof not retained", got)
		}
	}
	for _, change := range []assembledEmptyKey{
		{p, plain + " changed", textDLPAllPatterns, false},
		{p, plain, textDLPCardPatterns, false},
		{p, plain, textDLPAllPatterns, true},
	} {
		if p.emptyTerminal(change, false) {
			t.Fatal("cache key omitted context")
		}
	}
	other := reassemblyMarkerPlan(t)
	if other.emptyTerminal(key, false) {
		t.Fatal("proof crossed compiled plans")
	}
	// The first new value with a qualifying cue must still reach the terminal,
	// on every repetition; a finding is never a reusable empty proof.
	for range 2 {
		body := reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
		memo := &decodingMemo{reassemblyPlan: p, reassemblyDeferred: true}
		memo.reassemblyObserve(body)
		got := finishAssembled(TextDLPResult{Clean: true}, memo)
		memo.releaseProjection()
		if got.Clean || len(got.Matches) == 0 || p.emptyTerminal(assembledEmptyKey{p, body, textDLPAllPatterns, false}, false) {
			t.Fatal("qualifying candidate suppressed", got)
		}
	}
}

func TestReassemblyEmptyRetentionBounds(t *testing.T) {
	p := reassemblyMarkerPlan(t)
	key := assembledEmptyKey{p, "record", textDLPAllPatterns, false}
	p.emptyTerminalBytes = maxDecodeTotalBytes
	p.emptyTerminal(key, true)
	if len(p.emptyTerminals) != 0 {
		t.Fatal("byte retention limit ignored")
	}
	p.emptyTerminalBytes = 0
	p.emptyTerminals = make(map[assembledEmptyKey]struct{}, maxDecodeCandidates)
	for index := range maxDecodeCandidates {
		p.emptyTerminals[assembledEmptyKey{p, string(rune(index)), textDLPAllPatterns, false}] = struct{}{}
	}
	p.emptyTerminal(key, true)
	if len(p.emptyTerminals) != maxDecodeCandidates || p.emptyTerminal(key, false) {
		t.Fatal("entry retention limit ignored")
	}
}

func TestReassemblySharedObservationPromotion(t *testing.T) {
	p := reassemblyMarkerPlan(t)
	ctx, release := WithSharedDecodes(context.Background())
	defer release()
	body := reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
	source := strings.ReplaceAll(body, "!", "&#33;")
	memo := &decodingMemo{reassemblyPlan: p, reassemblyDeferred: true, shared: sharedDecodesFrom(ctx)}
	defer memo.releaseProjection()
	memo.reassemblySetKind(source, assembledDecoderView)
	memo.decode(source, true)
	memo.decode(source, true)
	if memo.reassemblyViewKinds[body].textual() {
		t.Fatal("binary ancestry lost")
	}
	memo.reassemblySetKind(source, assembledTextView)
	memo.decode(source, true)
	if !memo.reassemblyViewKinds[body].textual() {
		t.Fatal("independent text path not promoted")
	}
}

func TestReassemblyMetadataPoolClearsPayloads(t *testing.T) {
	memo := &decodingMemo{reassemblyPlan: reassemblyMarkerPlan(t), reassemblyDeferred: true}
	memo.reassemblyObserve("ordinary service status text")
	memo.reassemblyTextRoots = map[string]bool{"ordinary service status text": true}
	storage := memo.assembledProjectionStorage
	kinds, seen, roots, pending := memo.reassemblyViewKinds, memo.reassemblySeen, memo.reassemblyTextRoots, memo.reassemblyPending
	memo.releaseProjection()
	if len(kinds) != 0 || len(seen) != 0 || len(roots) != 0 || storage == nil {
		t.Fatal("metadata retained payload keys")
	}
	for _, text := range pending {
		if text != "" {
			t.Fatal("metadata retained pending payload")
		}
	}
	if memo.reassemblyViewKinds != nil || memo.reassemblySeen != nil || memo.reassemblyPending != nil {
		t.Fatal("released metadata still owned")
	}
	memo.releaseProjection()
}

func TestReassemblyMetadataPoolDropsOversize(t *testing.T) {
	memo := &decodingMemo{reassemblyDeferred: true}
	memo.assembledStorage()
	storage := memo.assembledProjectionStorage
	memo.reassemblyViewKinds = make(map[string]assembledViewKind)
	memo.reassemblySeen = make(map[string]int)
	memo.reassemblyTextRoots = make(map[string]bool)
	for index := range maxDecodeCandidates + 1 {
		key := string(rune(index))
		memo.reassemblyViewKinds[key] = assembledInputView
		memo.reassemblySeen[key] = index
		memo.reassemblyTextRoots[key] = true
	}
	memo.reassemblyPending = make([]string, maxDecodeCandidates+1)
	memo.releaseProjection()
	if storage.kinds != nil || storage.seen != nil || storage.roots != nil || storage.pending != nil {
		t.Fatal("oversized metadata recycled")
	}
}

func TestTextDecodingMemoReuse(t *testing.T) {
	for range 2 {
		memo := textDecodingMemo(nil, false, nil, false)
		if memo.incomplete || memo.reassemblyPlan != nil || memo.keywordMode || memo.reassemblyDecodedBytes != 0 || len(memo.reassemblyViewKinds) != 0 || !memo.reassemblyDeferred {
			t.Fatal("text memo retained state across scans")
		}
		memo.incomplete = true
		memo.keywordMode = true
		memo.reassemblyDecodedBytes = maxDecodeTotalBytes
		memo.reassemblySetKind("ordinary service status", assembledDecoderView)
		memo.releaseTextDecodingMemo()
	}
}

func TestReassemblyKindPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, regex string
		keywords    []string
		insensitive bool
	}{
		{"defaults", "", nil, true},
		{"literal", `MARK[0-9]{4}`, nil, true},
		{"class", `[0-9]{16}`, nil, false},
		{"keyword", `MARK[0-9]{4}`, []string{"lookup"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			if tc.regex != "" {
				cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Policy record", Regex: tc.regex, Keywords: tc.keywords, Severity: config.SeverityHigh})
			}
			sc := MustNew(cfg)
			defer sc.Close()
			if sc.reassemblyPlan.kindInsensitive != tc.insensitive {
				t.Fatal("incorrect ancestry requirement")
			}
			body := reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte(inspectionLimitAWSKey())))
			var expected []TextDLPMatch
			for _, insensitive := range []bool{false, tc.insensitive} {
				memo := textDecodingMemo(nil, false, nil, insensitive)
				memo.reassemblyPlan = sc.reassemblyPlan
				memo.reassemblyObserve(body)
				result := finishAssembled(TextDLPResult{Clean: true}, memo)
				if expected == nil {
					expected = result.Matches
				} else if strings.Join(matchNames(expected), ",") != strings.Join(matchNames(result.Matches), ",") {
					t.Fatal("ancestry optimization changed findings")
				}
				if result.Clean || HasInspectionLimit(result.Matches) {
					t.Fatal("credential not detected", result)
				}
				memo.releaseTextDecodingMemo()
			}
		})
	}
}

func TestReassemblyEmptyPatternScope(t *testing.T) {
	p, err := newReassemblyPlan([]*compiledPattern{{name: "Card record", re: regexp.MustCompile(`[0-9]{16}`), genericCard: true}})
	if err != nil {
		t.Fatal(err)
	}
	body := reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("1", 16))))
	first := &decodingMemo{reassemblyPlan: p, reassemblyDeferred: true, reassemblyPatterns: textDLPNonCardPatterns, reassemblyPatternLimit: textDLPNonCardPatterns}
	first.reassemblyObserve(body)
	if result := finishAssembled(TextDLPResult{Clean: true}, first); !result.Clean {
		t.Fatal("non-card scan found a card", result)
	}
	first.releaseProjection()
	for _, tc := range []struct {
		name    string
		scope   textDLPPatternSet
		pending bool
	}{
		{"separate", textDLPNonCardPatterns, false},
		{"shared", textDLPAllPatterns, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memo := &decodingMemo{reassemblyPlan: p, reassemblyDeferred: true, reassemblyPatterns: tc.scope, reassemblyPatternLimit: tc.scope}
			defer memo.releaseProjection()
			memo.reassemblyObserve(body)
			if (len(memo.reassemblyPending) > 0) != tc.pending {
				t.Fatal("empty proof used outside its pattern scope")
			}
			result := finishAssembled(TextDLPResult{Clean: true}, memo)
			if result.Clean == tc.pending || HasInspectionLimit(result.Matches) {
				t.Fatal("shared card coverage changed", result)
			}
		})
	}
}
