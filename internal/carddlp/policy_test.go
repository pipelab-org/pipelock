// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package carddlp

import (
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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

func TestCardCorroboratedKeyNames(t *testing.T) {
	for _, key := range []string{"card", "CC", "card_number", "Card No", "pan", "credit_card", "cvv"} {
		if !CorroboratedKey(key) {
			t.Fatalf("payment key %q not recognized", key)
		}
	}
	for _, key := range []string{"", "note", "id", "cards", "panel", "x\":\"note"} {
		if CorroboratedKey(key) {
			t.Fatalf("non-payment key %q recognized", key)
		}
	}
}

// Each family has 200,000 deterministic samples. The bytes are synthetic,
// never credentials; keeping the seed fixed makes any false hit reproducible.
func TestCardReceiptStrictIdentifiers(t *testing.T) {
	const seed = uint64(1973)
	hits := make(map[string]int)
	for sample := range uint64(200_000) {
		var input [16]byte
		binary.BigEndian.PutUint64(input[:8], seed)
		binary.BigEndian.PutUint64(input[8:], sample)
		raw := sha512.Sum512(input[:])
		uuid := func(version byte) string {
			b := [16]byte(raw[:16])
			b[6] = b[6]&15 | version<<4
			b[8] = b[8]&63 | 128
			h := hex.EncodeToString(b[:])
			return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
		}
		const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
		var ulid [26]byte
		for i := range ulid {
			ulid[i] = alphabet[raw[i]&31]
		}
		ulid[0] = alphabet[raw[0]&7]
		values := map[string]string{
			"uuid4": uuid(4), "uuid7": uuid(7),
			"request":   fmt.Sprintf("s1-r%x-m000000", raw[:16]),
			"req-uuid":  "req-" + uuid(4),
			"session":   "proxy.run." + hex.EncodeToString(raw[:16]),
			"sha256":    hex.EncodeToString(raw[:32]),
			"sha512":    hex.EncodeToString(raw[:]),
			"base64":    base64.StdEncoding.EncodeToString(raw[:32]),
			"base64url": base64.RawURLEncoding.EncodeToString(raw[:64]),
			"base32":    base32.StdEncoding.EncodeToString(raw[:32]),
			"ulid":      string(ulid[:]),
		}
		for kind, value := range values {
			// A dash-grouped traffic card that happens to use a UUID shape is
			// the ordinary grammar, not a strict-only false hit.
			traffic := Visit(value, false, func(c Candidate) bool {
				return !c.PublicExample && !IsPublicTestPAN(c.Digits)
			})
			strict := VisitStrict(value, func(Candidate) bool { return true })
			if strict && !traffic {
				hits[kind]++
			}
		}
	}
	for kind, count := range hits {
		t.Errorf("%s: %d strict-only identifier false hits", kind, count)
	}
}

func TestCardReceiptStrictKeepsTrafficGrammar(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	spaced := cardtest.Grouped(pan, " ")
	uuidShape := pan[:8] + "-" + pan[8:12] + "-" + pan[12:16] + "-0000-000000000000"
	for _, text := range []string{
		"ref-" + pan,
		"id:abc-" + spaced,
		"x" + pan,
		"?ref=a-" + pan,
		"req-" + pan,
		uuidShape,
		"https://api.vendor.example/ref-" + pan,
	} {
		traffic := Visit(text, false, func(c Candidate) bool {
			return !c.PublicExample && c.Digits == pan
		})
		strict := VisitStrict(text, func(c Candidate) bool { return c.Digits == pan })
		if !traffic || !strict {
			t.Errorf("traffic=%v strict=%v text=%q", traffic, strict, text)
		}
	}
	for _, text := range []string{"order_" + pan, "xx" + pan, "abc" + pan + "def"} {
		if Visit(text, false, func(c Candidate) bool { return !c.PublicExample }) || VisitStrict(text, func(Candidate) bool { return true }) {
			t.Errorf("letter-bounded tail became a card: %q", text)
		}
	}
}

func TestCardReceiptStrictIdentifierBoundaries(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	id := "97304a31-7c5d-4f4e-2560-" + "783810564780"
	// These samples are not traffic cards. The strict extra must not invent one.
	for _, text := range []string{"11111111-1111-4111-8111-111111111111", "s1-r6da769a44d020c06aa83633d966c593c-m000000"} {
		if Visit(text, false, func(c Candidate) bool { return !c.PublicExample }) || VisitStrict(text, func(Candidate) bool { return true }) {
			t.Fatalf("identifier rejected: %q", text)
		}
		assertSeparateCard(t, text, pan)
	}
	// The last two groups of id are a dash-grouped traffic card. Receipts keep it.
	for _, text := range []string{id, "req-" + id} {
		var want string
		if !Visit(text, false, func(c Candidate) bool {
			if c.PublicExample {
				return false
			}
			want = c.Digits
			return true
		}) || want == "" || !VisitStrict(text, func(c Candidate) bool { return c.Digits == want }) {
			t.Fatalf("traffic card inside identifier dropped: %q", text)
		}
		assertSeparateCard(t, text, pan)
	}
}

func assertSeparateCard(t *testing.T, text, pan string) {
	t.Helper()
	for _, sep := range []string{" ", "\t", "\r", "\n", ":", ",", "/"} {
		for _, content := range []string{text + sep + pan, pan + sep + text} {
			if !VisitStrict(content, func(c Candidate) bool { return c.Digits == pan }) {
				t.Fatalf("identifier hid separate card: %q", content)
			}
		}
	}
}

func TestCardReceiptStrictPaymentTokens(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, prefix := range []string{"card-", "visa-", "credit-card-", "card_number_", "pan"} {
		if !VisitStrict(prefix+cardtest.Grouped(pan, "-"), func(c Candidate) bool { return c.Digits == pan }) {
			t.Errorf("payment token missed: %s", prefix)
		}
	}
}

func TestCardReceiptUUIDShape(t *testing.T) {
	for _, tc := range []struct {
		token string
		want  bool
	}{
		{"", false},
		{"111111111111411181111111111111111111", false},
		{"g1111111-1111-4111-8111-111111111111", false},
		{"ABCDEF01-2345-4678-8123-0123456789AB", true},
		{"11111111-1111-4111-8111-111111111111", true},
	} {
		if got := canonicalUUID(tc.token); got != tc.want {
			t.Errorf("UUID %q=%v want=%v", tc.token, got, tc.want)
		}
	}
}
