// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "github.com/luckyPipewrench/pipelock/internal/config"

// shippedCardPattern matches the built-in contract in config/dlp_patterns.go.
const shippedCardPattern = `\b\d{4}(?:[- ]?\d){11,15}\b`

// RetriesCardPrefixes reports whether p is the built-in card rule with its
// luhn validator. Preset YAML copies the built-in rule without its Compiled
// marker, so rule name and regex both identify it. A separately named operator
// rule using the same regex keeps whole-match semantics.
func RetriesCardPrefixes(p config.DLPPattern) bool {
	return p.Name == "Credit Card Number" && p.Validator == config.ValidatorLuhn && p.Regex == shippedCardPattern
}

// AcceptsMatch applies the scanner's accepted-span policy to one regex hit for
// consumers that keep their own pattern loop, such as scan-diff and the
// project scan, so they agree with runtime scanning on card endpoints.
func AcceptsMatch(match string, validate func(string) bool, cardPrefixRetry bool) bool {
	if !cardPrefixRetry {
		return validate(match)
	}
	_, ok := acceptedCardEnd(match, func(end int) bool { return validate(match[:end]) })
	return ok
}

// acceptedCardEnd returns the end of the card in one ordinary FindAll hit of
// the shipped rule, judged by accept(end) over hit[:end]. The complete hit is
// tried first. The rule is greedy and its validator sees only what it is
// given, so a card followed by a separator and another digit ("12/27",
// "2 apples", "-3") yields one hit that fails the issuer or Luhn check.
//
// On that failure the start stays fixed and the end moves back to each
// separator already inside the hit, longest first. The separators are the
// rule's own [- ] class. A retried prefix keeps at least 15
// digits, which is both the rule's floor (\d{4} plus eleven repeats) and the
// validator's, so every retry is itself a complete match of the shipped rule
// ending on a word boundary. A retry never ends inside a contiguous digit
// group, never moves the start, and never looks past the original hit.
func acceptedCardEnd(hit string, accept func(end int) bool) (int, bool) {
	if accept(len(hit)) {
		return len(hit), true
	}
	digits := 0
	for i := range len(hit) {
		if hit[i] >= '0' && hit[i] <= '9' {
			digits++
		}
	}
	for end := len(hit) - 1; end > 0; end-- {
		switch c := hit[end]; {
		case c >= '0' && c <= '9':
			digits--
			continue
		case c != ' ' && c != '-':
			// Not a shipped-rule hit; judge only the complete candidate.
			return 0, false
		}
		if digits < 15 {
			break
		}
		if accept(end) {
			return end, true
		}
	}
	return 0, false
}
