// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package carddlp enumerates bounded, overlapping card candidates. Recognition
// depends only on each candidate's digits and internal presentation.
package carddlp

// Candidate is a validated card span in the supplied view. Offsets are bytes.
type Candidate struct {
	Start, End    int
	Digits        string
	PublicExample bool
}

// Visit calls yield for every issuer/Luhn-valid contiguous or canonically
// grouped candidate. Reconstructed URL views additionally admit arbitrary
// groupings. A false return continues enumeration; true stops it. Each digit
// group starts independently, so rejected prefixes cannot swallow neighbors.
// At most 19 digit groups can precede any separator run, so both modes
// take O(len(text)) work. Text mode limits separators to two characters.
func Visit(text string, reconstructed bool, yield func(Candidate) bool) bool {
	for start := 0; start < len(text); {
		if !digit(text[start]) {
			start++
			continue
		}
		next := start
		for next < len(text) && digit(text[next]) {
			next++
		}
		if leftBoundary(text, start) {
			var digits [MaxDigits]byte
			var groups [MaxDigits]int
			n, count, at, canonicalSeparators := 0, 0, start, true
			for at < len(text) && digit(text[at]) {
				groupStart := at
				for at < len(text) && digit(text[at]) && n < MaxDigits {
					digits[n] = text[at]
					n++
					at++
				}
				if at < len(text) && digit(text[at]) {
					break
				}
				groups[count] = at - groupStart
				count++
				if n >= MinDigits && rightBoundary(text, at) && (reconstructed || count == 1 || canonicalSeparators && canonical(groups[:count])) {
					value := string(digits[:n])
					if ValidCardNumber(value) && yield(Candidate{Start: start, End: at, Digits: value, PublicExample: IsPublicTestPAN(value)}) {
						return true
					}
				}
				sepStart := at
				for at < len(text) && ((reconstructed && urlSeparator(text[at])) || (!reconstructed && separator(text[at]) && at-sepStart < 2)) {
					canonicalSeparators = canonicalSeparators && text[at] != ','
					at++
				}
				if at == sepStart || at == len(text) || !digit(text[at]) || n == MaxDigits {
					break
				}
			}
		}
		start = next
	}
	return false
}

func canonical(g []int) bool {
	if len(g) == 3 {
		return g[0] == 4 && g[1] == 6 && (g[2] == 4 || g[2] == 5)
	}
	if len(g) != 4 && len(g) != 5 {
		return false
	}
	for _, size := range g[:3] {
		if size != 4 {
			return false
		}
	}
	if len(g) == 4 {
		return g[3] >= 2 && g[3] <= 4
	}
	return g[3] == 4 && g[4] >= 1 && g[4] <= 3
}

func digit(b byte) bool { return b >= '0' && b <= '9' }
func word(b byte) bool  { return digit(b) || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_' }

func separator(b byte) bool {
	return b == ' ' || b == '-' || b == '.' || b == '/' || b == '_' || b == ','
}

func leftBoundary(s string, at int) bool {
	if at == 0 || !word(s[at-1]) {
		return true
	}
	if s[at-1] == '_' && at > 1 && digit(s[at-2]) {
		return true
	}
	return !digit(s[at-1]) && (at == 1 || !word(s[at-2]))
}

func rightBoundary(s string, at int) bool {
	return at == len(s) || !word(s[at]) || s[at] == '_' && at+1 < len(s) && digit(s[at+1])
}

// URL punctuation is structure, not card data. Alphabetic components remain
// barriers; query-value concatenation is built by the URL parser separately.
func urlSeparator(b byte) bool {
	return b == ' ' || b >= '!' && b <= '/' || b >= ':' && b <= '@' || b >= '[' && b <= '`' || b >= '{' && b <= '~'
}
