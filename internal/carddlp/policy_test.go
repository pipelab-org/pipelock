// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package carddlp

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestCardCorroborationMonotonic(t *testing.T) {
	for _, prefix := range []string{"4019", "5191", "3712", "6011", "6229", "3528"} {
		size := 16
		if prefix == "3712" {
			size = 15
		}
		pan := cardtest.Issuer(prefix, size)
		for _, sep := range []string{"", " ", "-", ".", "\t", "\r", "\n", ","} {
			text := cardtest.Grouped(pan, sep)
			for _, label := range []string{"credit card: ", "visa ", "cvv ", `{"card":"`} {
				candidate := label + text
				if !VisitCorroborated(candidate, func(c Candidate) bool { return c.Digits == pan && Corroborated(candidate, c) }) {
					t.Fatalf("missing promotion: %q", candidate)
				}
			}
		}
	}
	pan := cardtest.Issuer("4019", 16)
	for _, context := range []string{"cardinal ", "account ", "credit ", strings.Repeat("x", 101) + " "} {
		text := context + pan
		c := Candidate{Start: len(context), End: len(text), Digits: pan}
		if Corroborated(text, c) {
			t.Fatalf("ambiguous context: %q", context)
		}
	}
	near := "visa " + strings.Repeat("界", 94) + " " + pan
	if !Corroborated(near, Candidate{Start: len(near) - len(pan), End: len(near), Digits: pan}) {
		t.Fatal("window measured bytes rather than runes")
	}
}

func TestCardReceiptStrictSplits(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for split := 1; split < len(pan); split++ {
		for _, sep := range []string{" ", "\t", "\r", "\n", ".", "-", "/", "_", ",", "\u200b", "\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2015", "\u2212", "\ufe63", "\uff0d", "\u00a0", "\u2007", "\u202f", "\u3000"} {
			for _, text := range []string{pan[:split] + sep + pan[split:], "1234" + sep + pan[:split] + sep + pan[split:] + sep + "5678", strings.Repeat("4242", 4) + sep + pan[:split] + sep + pan[split:] + sep + strings.Repeat("4242", 4)} {
				if !VisitStrict(text, func(Candidate) bool { return true }) {
					t.Fatalf("strict missed %q", text)
				}
			}
		}
	}
	for _, text := range []string{"", "123.456", strings.Repeat("4242", 4)} {
		if VisitStrict(text, func(Candidate) bool { return true }) {
			t.Fatalf("strict rejected public/clean %q", text)
		}
	}
}

func TestCardReceiptStrictPublishedFixtures(t *testing.T) {
	for pan := range publicTestPANs {
		if VisitStrict(pan, func(Candidate) bool { return true }) {
			t.Fatalf("published fixture rejected: %q", pan)
		}
	}
}

func TestCardReceiptStrictVisitorContinues(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	if !VisitStrict(pan+" word", func(Candidate) bool { return true }) {
		t.Fatal("missed run before word")
	}
	count := 0
	if VisitStrict(pan+" word "+pan, func(Candidate) bool { count++; return false }) || count < 2 {
		t.Fatalf("visitor stopped: %d", count)
	}
}

func TestCardEnclosingKeyBeyondWindow(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	text := strings.Repeat("x", 150) + " " + cardtest.Grouped(pan, "\t")
	if !VisitWithKey(text, "ｃａｒｄNumber", func(c Candidate) bool { return c.Digits == pan }) {
		t.Fatal("enclosing key lost past text window")
	}
	if VisitWithKey(text, "record", func(Candidate) bool { return true }) {
		t.Fatal("unrelated key promoted control join")
	}
}

func TestCardKeyTextMappedSpans(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	source := pan[:4] + "\t" + pan[4:]
	found := false
	if VisitTextWithKey(source, "card", func(c Candidate) bool {
		if c.Start != 0 || c.End != len(source) || c.Digits != pan {
			t.Fatalf("wrong mapped span: %+v", c)
		}
		found = true
		return false
	}) || !found {
		t.Fatal("key context did not enumerate mapped span")
	}
	if VisitTextWithKey(source, "record", func(Candidate) bool { return true }) {
		t.Fatal("unrelated key joined controls")
	}
	if !VisitTextWithKey(pan, "", func(Candidate) bool { return true }) {
		t.Fatal("ordinary early-stop path lost")
	}
	folded := "４" + pan[1:4] + "\t" + pan[4:]
	if !VisitTextWithKey(folded, "card", func(c Candidate) bool { return c.Start == 0 && c.End == len(folded) && c.Digits == pan }) {
		t.Fatal("Unicode key span lost original offsets")
	}
}
