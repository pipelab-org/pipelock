// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cardtest

import "strings"

// TextCase is plain text and its expected generic card verdict. Card, when
// set, is the exact text the finding must cover: a shorter accepted card, not
// the greedy hit that swallowed its neighbour.
type TextCase struct {
	Name  string
	Text  string
	Clean bool
	Card  string
}

// Issuer assembles a card of length digits that starts with prefix, choosing
// the Luhn check digit at runtime. Callers pass a prefix and length the
// scanner's issuer table accepts; this package cannot import that table.
func Issuer(prefix string, length int) string {
	body := prefix + strings.Repeat("0", length-len(prefix)-1)
	sum := 0
	for i := len(body) - 1; i >= 0; i-- {
		d := int(body[i] - '0')
		if (len(body)-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return body + string(rune('0'+(10-sum%10)%10))
}

// Grouped spells digits in groups of four joined by sep.
func Grouped(digits, sep string) string {
	var groups []string
	for len(digits) > 4 {
		groups = append(groups, digits[:4])
		digits = digits[4:]
	}
	return strings.Join(append(groups, digits), sep)
}

// TrailingDigitCases covers a card followed by another short numeric field.
// The shipped rule is greedy, so these neighbours used to extend the single
// hit past the card and fail its validator. Negative controls keep separator
// boundaries, checksums and contiguous digit groups meaningful.
func TrailingDigitCases() []TextCase {
	card := Number()
	spaced := Grouped(card, " ")
	dashed := Grouped(card, "-")
	amex := Issuer("37", 15)
	jcb := Issuer("3528", 16)
	invalid := card[:15] + "2"
	return []TextCase{
		{Name: "bare card", Text: "card " + card, Card: card},
		{Name: "labelled expiry", Text: "card " + card + " exp 12/27", Card: card},
		{Name: "unlabelled expiry", Text: "card " + card + " 12/27", Card: card},
		{Name: "quantity word", Text: "card " + card + " 2 apples", Card: card},
		{Name: "dash digit", Text: "card " + card + "-3", Card: card},
		{Name: "three trailing digits", Text: "card " + card + " 123", Card: card},
		{Name: "space grouped then expiry", Text: "card " + spaced + " 12/27", Card: spaced},
		{Name: "dash grouped then digit", Text: "card " + dashed + " 3", Card: dashed},
		{Name: "dash grouped then dash digit", Text: "card " + dashed + "-3", Card: dashed},
		{Name: "amex then quantity", Text: "card " + amex + " 2 items", Card: amex},
		{Name: "jcb then expiry", Text: "card " + jcb + " 12/27", Card: jcb},
		{Name: "comma before quantity", Text: "card " + card + ", 2 apples", Card: card},
		{Name: "four digit year", Text: "card " + card + " 2027", Card: card},
		{Name: "invalid checksum then expiry", Text: "card " + invalid + " 12/27", Clean: true},
		{Name: "invalid checksum grouped then digit", Text: "ref " + Grouped(invalid, " ") + " 3 items", Clean: true},
		{Name: "contiguous overlong token", Text: "id " + card + "2", Clean: true},
		{Name: "phone and order numbers", Text: "call 1 415 555 0134 order 1234 5678 9012 3456 7", Clean: true},
		{Name: "long trace id", Text: "trace=" + strings.Repeat("31", 16) + " status=200", Clean: true},
	}
}
