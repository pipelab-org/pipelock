// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

const cardPatternName = "Credit Card Number"

func trailingDigitScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	return s
}

// The finding must cover the card itself, not the greedy hit that swallowed
// its neighbour, so value hashes and redaction evidence name the card.
func TestTrailingDigitCardText(t *testing.T) {
	s := trailingDigitScanner(t)
	for _, tt := range cardtest.TrailingDigitCases() {
		t.Run(tt.Name, func(t *testing.T) {
			r := s.ScanTextForDLP(context.Background(), tt.Text)
			if r.Clean != tt.Clean {
				t.Fatalf("clean=%v want=%v matches=%+v", r.Clean, tt.Clean, r.Matches)
			}
			if tt.Clean {
				return
			}
			view := normalize.ForDLP(tt.Text)
			for _, m := range r.Matches {
				if m.PatternName != cardPatternName {
					continue
				}
				if m.span.ViewLabel != ViewDLPNormalized || view[m.span.ByteStart:m.span.ByteEnd] != tt.Card {
					t.Fatalf("span %+v covers %q, want the card", m.span, view[m.span.ByteStart:m.span.ByteEnd])
				}
				return
			}
			t.Fatalf("no card finding: %+v", r.Matches)
		})
	}
}

// URL DLP uses the same accepted-span loop. A hyphen survives in a URL. The
// percent-encoded control is caught in the raw URL view, where '%' already
// ends the hit, so it passes with or without the retry.
func TestTrailingDigitCardURL(t *testing.T) {
	s := trailingDigitScanner(t)
	card := cardtest.Number()
	invalid := card[:15] + "2"
	for _, tt := range []struct {
		name, url string
		blocked   bool
	}{
		{"path dash digit", "https://api.vendor.example/pay/" + card + "-3", true},
		{"query dash digit", "https://api.vendor.example/pay?ref=" + card + "-3", true},
		{"control: percent-encoded space expiry", "https://api.vendor.example/pay?ref=" + card + "%2012%2F27", true},
		{"invalid checksum dash digit", "https://api.vendor.example/pay/" + invalid + "-3", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := s.Scan(context.Background(), tt.url)
			if blocked := !r.Allowed && r.Scanner == ScannerDLP; blocked != tt.blocked {
				t.Fatalf("allowed=%v scanner=%q reason=%q want blocked=%v", r.Allowed, r.Scanner, r.Reason, tt.blocked)
			}
		})
	}
}

// matches is the boolean path; it must agree with the span path.
func TestTrailingDigitCardBooleanPath(t *testing.T) {
	s := trailingDigitScanner(t)
	var card *compiledPattern
	for _, p := range s.dlpPatterns {
		if p.name == cardPatternName {
			card = p
		}
	}
	if card == nil || !card.cardPrefixRetry {
		t.Fatal("shipped card rule did not enable prefix retry")
	}
	for _, tt := range cardtest.TrailingDigitCases() {
		if got := card.matches(tt.Text); got == tt.Clean {
			t.Fatalf("%s: matches=%v want=%v", tt.Name, got, !tt.Clean)
		}
	}
}

// Only the canonical rule retries. An operator regex carrying the luhn
// validator keeps whole-match semantics, so it still judges the greedy hit.
func TestTrailingDigitRetryScopedToShippedRule(t *testing.T) {
	custom := config.DLPPattern{Name: "Operator Card", Regex: `\b\d{4}(?:[- ]?\d){11,15}(?:\b)`, Severity: config.SeverityHigh, Validator: config.ValidatorLuhn}
	exactCustom := config.DLPPattern{Name: "Operator exact card", Regex: shippedCardPattern, Severity: config.SeverityHigh, Validator: config.ValidatorLuhn}
	if RetriesCardPrefixes(exactCustom) {
		t.Fatal("operator pattern with the shipped regex gained prefix retry")
	}
	if RetriesCardPrefixes(custom) || !RetriesCardPrefixes(config.DLPPattern{Name: cardPatternName, Regex: shippedCardPattern, Validator: config.ValidatorLuhn}) ||
		RetriesCardPrefixes(config.DLPPattern{Regex: shippedCardPattern, Validator: config.ValidatorMod97}) {
		t.Fatal("prefix retry scope is wrong")
	}
	for _, pattern := range []config.DLPPattern{custom, exactCustom} {
		t.Run(pattern.Name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			cfg.DLP.Patterns = []config.DLPPattern{pattern}
			s := MustNew(cfg)
			t.Cleanup(s.Close)
			card := cardtest.Number()
			if r := s.ScanTextForDLP(context.Background(), "card "+card); r.Clean {
				t.Fatal("operator luhn pattern lost its whole-card match")
			}
			for _, m := range s.ScanTextForDLP(context.Background(), "card "+card+" 2 apples").Matches {
				if m.PatternName == pattern.Name {
					t.Fatal("operator luhn pattern was widened to retry shorter candidates")
				}
			}
		})
	}
}

func TestAcceptsMatch(t *testing.T) {
	card := cardtest.Number()
	if !AcceptsMatch(card+" 2", validateLuhn, true) || AcceptsMatch(card+" 2", validateLuhn, false) || !AcceptsMatch(card, validateLuhn, false) {
		t.Fatal("AcceptsMatch does not follow the accepted-span policy")
	}
}
