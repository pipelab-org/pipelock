// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
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

func TestCardPolicyPunctuationLabels(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.CardBareAction = config.ActionWarn
	sc := MustNew(cfg)
	defer sc.Close()
	pan := cardtest.Issuer("4019", 16)
	for _, label := range []string{"card:", "card#", "cc#", "card: "} {
		if sc.ScanTextForDLPQuiet(t.Context(), label+pan).Clean {
			t.Errorf("label %q did not block", label)
		}
	}
	if !sc.ScanTextForDLPQuiet(t.Context(), "cardinal "+pan).Clean {
		t.Fatal("cardinal corroborated")
	}
}

func TestCardReceiptEmptyPatternsDecode(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = nil
	cfg.DLP.ScanEnv = false
	disabled := false
	cfg.SeedPhraseDetection.Enabled = &disabled
	sc := MustNew(cfg)
	defer sc.Close()
	pan := cardtest.Issuer("4019", 16)
	for _, value := range []string{base64.StdEncoding.EncodeToString([]byte(pan)), hex.EncodeToString([]byte(pan)), url.QueryEscape(cardtest.Grouped(pan, "\t"))} {
		if sc.ScanTextForReceiptDLP(t.Context(), value).Clean {
			t.Errorf("encoded receipt passed: %q", value)
		}
	}
}

func TestCardPolicyTypedDerivedParity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.CardBareAction = config.ActionWarn
	sc := MustNew(cfg)
	defer sc.Close()
	pan := cardtest.Issuer("4019", 16)
	for _, suffix := range []string{".0", "e0", ".00e0"} {
		for _, body := range []string{
			`{"value":` + pan + suffix + `}`,
			`{"value":` + pan + suffix + `,"other":"tail"}`,
			`[` + pan + suffix + `,null]`,
		} {
			atoms := extract.AllStringsFromJSONResult(json.RawMessage(body)).Atoms
			var parts []string
			for _, a := range atoms {
				parts = append(parts, a.Text)
			}
			raw := sc.ScanTextForDLPQuiet(t.Context(), body)
			typed := sc.ScanRequestBodyTextPartsWithCardAtoms(t.Context(), parts, atoms, extract.BodyDLPJoinSeparator)
			if raw.Clean || typed.Clean {
				t.Errorf("%s raw clean=%v typed clean=%v", body, raw.Clean, typed.Clean)
			}
		}
	}
	body := `{"value":"` + pan + `,"}`
	atoms := extract.AllStringsFromJSONResult(json.RawMessage(body)).Atoms
	if !sc.ScanRequestBodyTextPartsWithCardAtoms(t.Context(), []string{pan + ","}, atoms, ".").Clean {
		t.Fatal("string comma gained numeric provenance")
	}
}

func TestCardPolicyWarnRulePartition(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	for i := range cfg.DLP.Patterns {
		if cfg.DLP.Patterns[i].Validator == "luhn" {
			cfg.DLP.Patterns[i].Action = config.ActionWarn
		}
	}
	sc := MustNew(cfg)
	defer sc.Close()
	pan := cardtest.Issuer("4019", 16)
	atoms := []extract.DLPAtom{{Text: pan, Card: pan, ContextKey: "card"}}
	res := sc.ScanRequestBodyTextPartsWithCardAtoms(t.Context(), []string{pan}, atoms, ".")
	if !res.Clean || len(res.Matches) != 0 || len(res.InformationalMatches) == 0 {
		t.Fatalf("warn partition: %+v", res)
	}
}

func TestCardReceiptURLMemoPolicy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := MustNew(cfg)
	defer sc.Close()
	memo := textDecodingMemo(nil, false, nil, false)
	defer memo.releaseTextDecodingMemo()
	memo.cardSource = true
	memo.receiptCards = true
	text := "https://api.vendor.example/?value=" + url.QueryEscape(cardtest.Grouped(strings.Repeat("4242", 4), "\t"))
	_ = sc.textURLCardMatches(t.Context(), text, memo)
	if memo.urlCardDecodes == nil || !memo.urlCardDecodes.receiptCards {
		t.Fatal("receipt policy lost by deferred URL memo")
	}
}

// A request context that ends during the typed-atom card scans must leave the
// merged result unverified, never clean.
func TestCardTypedAtomsCanceledScanIsIncomplete(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	atoms := []extract.DLPAtom{{Card: "note", Key: true}, {Text: "1.0", Card: "1", Number: true, ContextKey: "card"}}
	result := s.ScanRequestBodyTextPartsWithCardAtoms(ctx, []string{"note", "1.0"}, atoms, " ")
	if result.Clean || !result.Incomplete {
		t.Fatalf("canceled typed-atom scan reported clean=%v incomplete=%v", result.Clean, result.Incomplete)
	}
}
