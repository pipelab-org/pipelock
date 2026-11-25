// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/carddlp"
	"github.com/luckyPipewrench/pipelock/internal/normalize"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
)

func TestCardPolicyTiers(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, action := range []string{config.ActionBlock, config.ActionWarn} {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.CardBareAction = action
		s, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		for _, tc := range []struct {
			name, text string
			block      bool
		}{
			{"bare", pan, action == config.ActionBlock},
			{"derived exponent", pan + "e0", true},
			{"derived fraction", pan + ".0", true},
			{"grouped", cardtest.Grouped(pan, " "), true},
			{"noncanonical", pan[:8] + "  " + pan[8:], true},
			{"decimal", "F27=" + pan[:4] + "." + pan[4:], false},
			{"payment decimal", "credit card: " + pan[:4] + "." + pan[4:], true},
			{"payment controls", "visa " + cardtest.Grouped(pan, "\t"), true},
			{"controls", cardtest.Grouped(pan, "\n"), false},
			{"legacy public controls", "0." + cardtest.Grouped(strings.Repeat("4242", 4), "\t"), true},
			{"expiry", pan + " 12/28", true},
			{"calendar date", pan + " 12 / 10 / 2028", action == config.ActionBlock},
			{"key", `{"card":"` + pan + `"}`, true},
			{"url", "https://api.vendor.example/" + pan, true},
			{"encoded", base64.StdEncoding.EncodeToString([]byte(pan)), true},
			{"obfuscated", pan[:4] + "\u200b" + pan[4:], true},
			{"warning then high", pan + "; " + cardtest.Grouped(cardtest.Issuer("5191", 16), "-"), true},
		} {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				res := s.ScanTextForDLP(context.Background(), tc.text)
				if got := !res.Clean; got != tc.block {
					t.Fatalf("block=%v want %v: %+v", got, tc.block, res)
				}
				if tc.name == "bare" && action == config.ActionWarn && len(res.InformationalMatches) == 0 {
					t.Fatal("missing warning")
				}
			})
		}
	}
}

func TestCardPolicyTypedKeyContext(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.CardBareAction = config.ActionWarn
	s := MustNew(cfg)
	defer s.Close()
	atoms := []extract.DLPAtom{{Text: "card", Card: "card", Key: true}, {Text: pan, Card: pan}}
	result := s.ScanRequestBodyTextPartsWithCardAtoms(t.Context(), []string{"card", pan}, atoms, extract.BodyDLPJoinSeparator)
	if result.Clean {
		t.Fatal("enclosing card key lost")
	}
}

func TestCardPolicyReconstructedStringsStayHigh(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.CardBareAction = config.ActionWarn
	s := MustNew(cfg)
	defer s.Close()
	text := `["` + pan[:5] + `","` + pan[5:] + `"]`
	if result := s.ScanTextForDLP(t.Context(), text); result.Clean {
		t.Fatal("reconstructed string card was downgraded")
	}
}

func TestCardLiteralCandidateMapping(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, tc := range []struct {
		source  string
		literal bool
	}{
		{pan, true},
		{"x\u200b " + pan, true},
		{"\u1100\u1161 " + pan, true},
		{pan[:4] + "\u200b" + pan[4:], false},
		{"４" + pan[1:], false},
	} {
		view := normalize.ForCardText(tc.source)
		start := strings.Index(view, pan)
		c := carddlp.Candidate{Start: start, End: start + len(pan), Digits: pan}
		if got := newCardLiteralProof(tc.source, view).literal(c); got != tc.literal {
			t.Fatalf("%q literal=%v", tc.source, got)
		}
	}
	if newCardLiteralProof("opaque", pan).literal(carddlp.Candidate{Start: 0, End: len(pan), Digits: pan}) {
		t.Fatal("unmapped source treated as literal")
	}
}

func TestCardReceiptModeDoesNotPersist(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.CardBareAction = config.ActionWarn
	sc := MustNew(cfg)
	defer sc.Close()
	ctx := sharedDecodeContext(t)
	pan := cardtest.Issuer("4019", 16)
	for _, text := range []string{pan, pan[:4] + "." + pan[4:], base64.StdEncoding.EncodeToString([]byte(cardtest.Grouped(pan, "\t")))} {
		if !sc.ScanTextForDLPQuiet(ctx, text).Clean {
			t.Fatalf("traffic floor changed before receipt: %q", text)
		}
		if sc.ScanTextForReceiptDLP(ctx, text).Clean {
			t.Fatalf("strict receipt passed: %q", text)
		}
		if !sc.ScanTextForDLPQuiet(ctx, text).Clean {
			t.Fatalf("receipt policy persisted into traffic: %q", text)
		}
	}
}

func TestCardPolicyManyUnicodeWarningsRetainHigh(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.CardBareAction = config.ActionWarn
	sc := MustNew(cfg)
	defer sc.Close()
	pan := cardtest.Issuer("4019", 16)
	text := strings.Repeat("note\u200b "+pan+"; ", 128)
	result := sc.ScanTextForDLPQuiet(t.Context(), text)
	if !result.Clean || len(result.InformationalMatches) == 0 {
		t.Fatal("unrelated Unicode changed bare-card warnings")
	}
	if sc.ScanTextForDLPQuiet(t.Context(), text+pan[:4]+"\u200b"+pan[4:]).Clean {
		t.Fatal("earlier warnings hid obfuscated candidate")
	}
}
