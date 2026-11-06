// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestPolicyPatternClasses(t *testing.T) {
	for _, tc := range []struct {
		expr, value string
		decoder     bool
	}{
		{`EMP[0-9]{6}`, "EMP123456", true},
		{`(?i)internal-[a-z0-9]{1,40}`, "internal-abc123", true},
		{`ACME_[A-Z0-9]{32}`, "ACME_" + strings.Repeat("Q", 32), true},
		{`[0-9]{16}`, strings.Repeat("0", 16), false},
		{`[A-F0-9]{40}`, strings.Repeat("A", 40), false},
		{`EMP[0-9]{6}|[0-9]{16}`, "EMP123456", false},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Policy probe", Regex: tc.expr, Severity: config.SeverityHigh})
			sc := MustNew(cfg)
			defer sc.Close()
			id := slices.IndexFunc(sc.reassemblyPlan.patterns, func(p *compiledPattern) bool { return p.name == "Policy probe" })
			if id < 0 || sc.reassemblyPlan.assembled.decoderAllowed[id] != tc.decoder {
				t.Fatal("wrong pattern class", id)
			}
			body := strings.Repeat("!", maxReassembledTokenLen+1) + reassemblyBang(hex.EncodeToString([]byte(tc.value)))
			for _, kind := range []assembledViewKind{assembledInputView, assembledTextView, assembledDecoderView} {
				memo := &decodingMemo{reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true}
				memo.reassemblyObserveView(body, kind)
				result := finishAssembled(TextDLPResult{Clean: true}, memo)
				found := slices.Contains(matchNames(result.Matches), "Policy probe")
				if found != (kind.textual() || tc.decoder) || HasInspectionLimit(result.Matches) {
					t.Errorf("kind=%d found=%v result=%v", kind, found, result)
				}
			}
			nested := assembledNestedHexAdmitted(sc.reassemblyPlan, hex.EncodeToString([]byte(body)), &assembledBudget{})
			if slices.Contains(matchNames(nested.findings), "Policy probe") != tc.decoder || nested.incomplete {
				t.Fatal("nested path crossed pattern policy", nested.findings)
			}
		})
	}
}

func TestPolicyDigitBodies(t *testing.T) {
	if testing.Short() {
		t.Skip("large digit witnesses")
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	defer sc.Close()
	for _, size := range []int{512 << 10, 1 << 20, 4 << 20} {
		for _, tail := range []bool{false, true} {
			for _, inbound := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/tail=%v/inbound=%v", size, tail, inbound), func(t *testing.T) {
					body := strings.Repeat("30", size/2)
					if tail {
						body += reassemblyBang(hex.EncodeToString([]byte(inspectionLimitAWSKey())))
					}
					ctx := context.Background()
					if inbound {
						ctx = WithInboundDirection(ctx)
					}
					r := sc.ScanTextForDLP(ctx, body)
					found := slices.Contains(matchNames(r.Matches), "AWS Access ID")
					t.Logf("bytes=%d tail=%v inbound=%v clean=%v names=%v", len(body), tail, inbound, r.Clean, matchNames(r.Matches))
					if found != tail || HasInspectionLimit(r.Matches) || r.Incomplete || r.Clean == tail {
						t.Fatal("digit witness failed", r)
					}
				})
			}
		}
	}
}

func TestPolicyInboundSignal(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		memo := &decodingMemo{reassemblyPlan: reassemblyTestPlan(t), reassemblyDeferred: true, reassemblyInbound: inbound, assembledBytes: maxDecodeTotalBytes}
		memo.reassemblyObserve(reassemblyBang(hex.EncodeToString([]byte(inspectionLimitAWSKey()))))
		r := finishAssembled(TextDLPResult{Clean: true}, memo)
		if r.Incomplete || r.Clean != inbound || HasInspectionLimit(r.Matches) == inbound {
			t.Fatal("wrong directional result", r)
		}
		if inbound && (len(r.Matches) != 1 || !r.Matches[0].IsInformational() || !r.Matches[0].Warn || CardRunAction(r.Matches, config.ActionBlock) != config.ActionWarn) {
			t.Fatal("partial signal enforces or is absent", r)
		}
	}
}

func TestPolicyProjectionClasses(t *testing.T) {
	for _, decoderFirst := range []bool{false, true} {
		memo := &decodingMemo{reassemblyPlan: reassemblyTestPlan(t), reassemblyDeferred: true}
		first, second := assembledInputView, assembledDecoderView
		if decoderFirst {
			first, second = second, first
		}
		a := strings.Repeat("30!", 100)
		b := strings.Repeat("3!0", 100)
		memo.reassemblyObserveView(a, first)
		memo.reassemblyObserveView(b, second)
		if memo.assembledSkip(0) != 0 {
			t.Fatal("first view skipped")
		}
		got := memo.assembledSkip(1)
		if decoderFirst && got != 0 || !decoderFirst && got != 31 {
			t.Fatal("projection crossed pattern policy", decoderFirst, got)
		}
	}
}

func TestPolicyDerivedBinaryViews(t *testing.T) {
	var absent *decodingMemo
	absent.reassemblySetKind("absent", assembledInputView)
	absent.reassemblyDerive("absent", "derived")
	disabled := &decodingMemo{}
	disabled.reassemblySetKind("disabled", assembledTextView)
	if disabled.reassemblyViewKinds != nil {
		t.Fatal("decoder-only caller allocated terminal state")
	}
	m := &decodingMemo{reassemblyPlan: reassemblyTestPlan(t), reassemblyDeferred: true}
	m.reassemblySetKind("binary root", assembledDecoderView)
	m.reassemblyDerive("binary root", "normalized view")
	m.reassemblyDerive("normalized view", strings.Repeat("segment", 20))
	if m.reassemblyViewKinds[strings.Repeat("segment", 20)].textual() {
		t.Fatal("binary ancestry lost")
	}
	m.reassemblyObserveView(strings.Repeat("segment", 20), assembledTextView)
	if !m.reassemblyViewKinds[strings.Repeat("segment", 20)].textual() {
		t.Fatal("independent text path ignored")
	}
}

func TestPolicyLateTextPath(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Policy probe", Regex: `[0-9]{16}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	defer sc.Close()
	body := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("0", 16))))
	m := &decodingMemo{reassemblyPlan: sc.reassemblyPlan}
	m.reassemblyObserveView(body, assembledDecoderView)
	if len(m.reassemblyFindings) != 0 {
		t.Fatal("class-only pattern entered binary view")
	}
	m.reassemblyDerive("independent input text", body)
	if !slices.Contains(matchNames(m.reassemblyFindings), "Policy probe") {
		t.Fatal("later exact text path lost configured coverage")
	}
}

func TestPolicyCachedTextPath(t *testing.T) {
	body := reassemblyBang(hex.EncodeToString([]byte(inspectionLimitAWSKey())))
	source := strings.ReplaceAll(body, "!", "&#33;")
	m := &decodingMemo{reassemblyPlan: reassemblyTestPlan(t), reassemblyDeferred: true}
	m.reassemblySetKind(source, assembledDecoderView)
	m.decode(source, true)
	if m.reassemblyViewKinds[body].textual() {
		t.Fatal("binary cached path became textual")
	}
	m.reassemblyObserveView(source, assembledInputView)
	m.decode(source, true)
	if !m.reassemblyViewKinds[body].textual() {
		t.Fatal("cached decode ignored a later exact text path")
	}
}

func TestPolicyImageSurroundingText(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Policy probe", Regex: `[0-9]{16}`, Severity: config.SeverityHigh})
	sc := MustNew(cfg)
	defer sc.Close()
	value := strings.Repeat("0", 16)
	encoded := reassemblyBang(hex.EncodeToString([]byte(value)))
	image := dataURLForPNGBytes(t, pngWithLiteralInTextChunk(t, "ordinary text"))
	body := strings.Repeat("a!", maxReassembledTokenLen+1) + encoded[:len(encoded)/2] + image + encoded[len(encoded)/2:]
	r := sc.ScanTextForDLP(t.Context(), body)
	identity := sha256.Sum256([]byte(value))
	if !slices.ContainsFunc(r.Matches, func(m TextDLPMatch) bool {
		return m.PatternName == "Policy probe" && m.hasValueIdentity && m.valueIdentity == identity
	}) {
		t.Fatal("image removal lost surrounding text coverage", r)
	}
}

func TestPolicyVerifiedImageViews(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	defer sc.Close()
	image := dataURLForPNGBytes(t, randomPNG(t, 23))
	body := `{"image":"` + image + `","message":"ordinary text"}`
	memo := &decodingMemo{reassemblyDeferred: true}
	defer memo.releaseProjection()
	result := sc.scanTextForDLPWithDecodes(t.Context(), body, textDLPOptions{patterns: textDLPAllPatterns, scanSecretLeak: true}, memo)
	result = finishAssembled(result, memo)
	if slices.Contains(memo.reassemblyPending, body) {
		t.Fatal("removed image carrier entered terminal inspection")
	}
	text := exciseVerifiedImageDataURLs(body)
	retained := exciseImagesRetainingDecodedForDLP(body)
	if !slices.Contains(memo.reassemblyPending, text) || !slices.Contains(memo.reassemblyPending, retained) {
		t.Fatal("image removal lost text or retained binary inspection")
	}
	if !memo.reassemblyViewKinds[text].textual() || memo.reassemblyViewKinds[retained].textual() {
		t.Fatal("image removal changed view eligibility")
	}
	if !result.Clean || result.Incomplete || HasInspectionLimit(result.Matches) {
		t.Fatal("verified image changed admission", result)
	}
}
