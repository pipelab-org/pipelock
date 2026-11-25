// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package carddlp

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// Payment vocabulary is based on Microsoft Purview's credit card SIT:
// https://learn.microsoft.com/en-us/purview/sit-defn-credit-card-number
// This subset excludes ambiguous standalone words such as account and credit.
// The symmetric 100-rune window is Pipelock policy, not Purview's 300 characters.
var (
	paymentContext = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:credit[ _-]*card|debit[ _-]*card|payment[ _-]*card|bank[ _-]*card|charge[ _-]*card|card[ _-]*(?:number|num|no|#|holder)|cc[ _-]*(?:number|num)|ccn|pan|primary[ _-]*account[ _-]*number|payment[ _-]*account[ _-]*number|visa|master[ _-]*card|amex|american[ _-]*express|diners[ _-]*club|unionpay|discover[ _-]*card|jcb[ _-]*card|cvv2?|cvc2?|security[ _-]*code|verification[ _-]*code|exp[ _-]*(?:date|month|year)|expiration|expiry|valid[ _-]*thru|good[ _-]*thru)(?:$|[^a-z0-9])|(?:^|[^a-z0-9])(?:card[ _-]*[:#]|cc[ _-]*#)`)
	paymentKeyName = regexp.MustCompile(`(?i)^(?:card|cc|card[ _-]*(?:no|number)|pan)$`)
	paymentKey     = regexp.MustCompile(`(?i)"(?:card|cc|card[ _-]*(?:no|number)|pan)"\s*:\s*"?[^"{}]*$`)
	expiryContext  = regexp.MustCompile(`\b(?:0[1-9]|1[0-2])\s*/\s*(?:[0-9]{4}|[0-9]{2})\b`)
)

// Corroborated is a positive-only promotion. Adding a payment label, expiry,
// or enclosing JSON card key never removes a candidate admitted by Visit.
func Corroborated(text string, c Candidate) bool {
	left, right := c.Start, c.End
	for n := 0; n < 100 && left > 0; n++ {
		_, size := utf8.DecodeLastRuneInString(text[:left])
		left -= size
	}
	for n := 0; n < 100 && right < len(text); n++ {
		_, size := utf8.DecodeRuneInString(text[right:])
		right += size
	}
	context := text[left:right]
	return paymentContext.MatchString(context) || hasCardExpiry(context) || paymentKey.MatchString(text[left:c.Start])
}

func hasCardExpiry(text string) bool {
	for _, span := range expiryContext.FindAllStringIndex(text, -1) {
		before, after := strings.TrimSpace(text[:span[0]]), strings.TrimSpace(text[span[1]:])
		if !strings.HasSuffix(before, "/") && !strings.HasPrefix(after, "/") {
			return true
		}
	}
	return false
}

// CorroboratedKey recognizes an enclosing payment key independently of the
// value's length. A field label is schema evidence, not a nearby text window.
func CorroboratedKey(key string) bool {
	key = normalize.ForCardText(key)
	return paymentContext.MatchString(key) || paymentKeyName.MatchString(key)
}

// VisitWithKey applies the same candidate grammar with an enclosing key.
func VisitWithKey(text, key string, yield func(Candidate) bool) bool {
	if CorroboratedKey(key) {
		return visit(text, candidateView{strictSeparators: true}, yield)
	}
	return VisitCorroborated(text, yield)
}

// VisitCorroborated joins the ordinary presentation floor with additional
// separator-joined candidates only when positive payment context is present.
func VisitCorroborated(text string, yield func(Candidate) bool) bool {
	if Visit(text, false, yield) {
		return true
	}
	return visit(text, candidateView{strictSeparators: true}, func(c Candidate) bool { return Corroborated(text, c) && yield(c) })
}

// VisitStrict scans receipt content, including every bounded digit window in a
// separator-joined run. Neighbour digits and public fixtures cannot hide a real
// card. Identifier tokens are barriers: their numeric substrings are not
// standalone card presentations. This does not strip arbitrary receipt text.
// Returned offsets refer to the ForCardText-normalized view.
func VisitStrict(text string, yield func(Candidate) bool) bool {
	text = normalize.ForCardText(text)
	var run strings.Builder
	var offsets []int
	flush := func() bool {
		digits := run.String()
		publicEnds := make([]int, len(digits))
		for public := range publicTestPANs {
			for offset := 0; offset < len(digits); {
				i := strings.Index(digits[offset:], public)
				if i < 0 {
					break
				}
				i += offset
				for start := i; start+MinDigits <= i+len(public); start++ {
					publicEnds[start] = max(publicEnds[start], i+len(public))
				}
				offset = i + 1
			}
		}
		for start := 0; start < len(digits); start++ {
			for size := MinDigits; size <= MaxDigits && start+size <= len(digits); size++ {
				value := digits[start : start+size]
				public := start+size <= publicEnds[start]
				if !public && ValidCardNumber(value) && !IsPublicTestPAN(value) && yield(Candidate{Start: offsets[start], End: offsets[start+size-1] + 1, Digits: value}) {
					return true
				}
			}
		}
		run.Reset()
		offsets = offsets[:0]
		return false
	}
	barriers := strictIdentifierSpans(text)
	nextBarrier := 0
	for i := 0; i < len(text); {
		if nextBarrier < len(barriers) && i == barriers[nextBarrier].start {
			if flush() {
				return true
			}
			i = barriers[nextBarrier].end
			nextBarrier++
			continue
		}
		size := 1
		switch {
		case digit(text[i]):
			run.WriteByte(text[i])
			offsets = append(offsets, i)
		case separator(text[i]) || controlSeparator(text[i]):
		default:
			var unicodeSeparator bool
			if text[i] >= utf8.RuneSelf {
				var r rune
				r, size = utf8.DecodeRuneInString(text[i:])
				unicodeSeparator = strictUnicodeSeparator(r)
			}
			if !unicodeSeparator && flush() {
				return true
			}
		}
		i += size
	}
	return flush()
}

// strictUnicodeSeparator reports the non-ASCII dashes, minus signs and spaces
// that receipts treat like their ASCII separators, so a typographic dash or a
// no-break space cannot split a card out of strict receipt scanning. Unicode
// classifies them as dash punctuation (Pd) or space separators (Zs); U+2212
// MINUS SIGN is a math symbol and is listed explicitly.
func strictUnicodeSeparator(r rune) bool {
	return r == '\u2212' || unicode.Is(unicode.Pd, r) || unicode.Is(unicode.Zs, r)
}

// identifierByte includes UUID/request-ID separators and both base64
// alphabets. Padding terminates the token.
// Punctuation outside this alphabet and whitespace terminate the token. A
// digit-only token is still scanned, however long or oddly grouped it is.
func identifierByte(b byte) bool {
	return word(b) || b == '-' || b == '/' || b == '+'
}

func asciiLetter(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }

// canonicalUUID recognizes the complete hexadecimal 8-4-4-4-12 wire shape,
// including the rare UUID whose hex groups happen to contain only digits.
func canonicalUUID(token string) bool {
	if len(token) != 36 {
		return false
	}
	for i := range len(token) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if token[i] != '-' {
				return false
			}
			continue
		}
		b := token[i]
		isHex := digit(b) || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
		if !isHex {
			return false
		}
	}
	return true
}

// A payment label attached to a digit presentation is positive context, not
// an opaque identifier (for example card-4019-...). Do not exempt its digits.
func paymentToken(token string) bool {
	first := strings.IndexFunc(token, func(r rune) bool { return r >= '0' && r <= '9' })
	if first <= 0 || !CorroboratedKey(strings.TrimRight(token[:first], "-_/")) {
		return false
	}
	for i := first; i < len(token); i++ {
		if asciiLetter(token[i]) {
			return false
		}
	}
	return true
}

type identifierSpan struct{ start, end int }

// Slashes separate path components and card groups. Only a canonical binary
// digest may claim its full slash-bearing token as base64; other tokens are
// classified component by component so folder/PAN and UUID/PAN keep scanning.
func strictIdentifierSpans(text string) []identifierSpan {
	var spans []identifierSpan
	opaque := func(token string) bool {
		letters := strings.IndexFunc(token, func(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }) >= 0
		return letters && !paymentToken(token) || canonicalUUID(token)
	}
	for start := 0; start < len(text); {
		if !identifierByte(text[start]) {
			start++
			continue
		}
		end := start + 1
		for end < len(text) && identifierByte(text[end]) {
			end++
		}
		token := text[start:end]
		if !strings.Contains(token, "/") || encodedDigestToken(token) {
			if opaque(token) {
				spans = append(spans, identifierSpan{start, end})
			}
		} else {
			offset := start
			for _, part := range strings.Split(token, "/") {
				if opaque(part) {
					spans = append(spans, identifierSpan{offset, offset + len(part)})
				}
				offset += len(part) + 1
			}
		}
		start = end
	}
	return spans
}

func encodedDigestToken(token string) bool {
	// Padding ends the lexical token. Raw decoding accepts either padded
	// digest's body or a deliberately unpadded SHA-256/SHA-512 representation.
	if len(token) != 43 && len(token) != 86 {
		return false
	}
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(token)
	return err == nil && (len(decoded) == 32 || len(decoded) == 64)
}
