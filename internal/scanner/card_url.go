// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/carddlp"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// appendHostnameCardTargets isolates numeric label runs from nonnumeric sibling
// labels. PSL suffix removal and IP exclusion use the existing hostname helper.
func appendHostnameCardTargets(targets []dlpTarget, hostname string) []dlpTarget {
	prefix, ok := hostnameEncodedPrefix(hostname)
	if !ok {
		return targets
	}
	labels := strings.Split(prefix, ".")
	for start := range labels {
		var digits strings.Builder
		for _, label := range labels[start:] {
			value := strings.ReplaceAll(label, "-", "")
			if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				break
			}
			digits.WriteString(value)
			if digits.Len() > 19 {
				break
			}
			if digits.Len() >= 14 {
				targets = append(targets, dlpTarget{digits.String(), dlpViewLabel("subdomain_card"), ""})
			}
		}
	}
	return targets
}

func (s *Scanner) textURLCardMatches(ctx context.Context, text string, decodes *decodingMemo) []TextDLPMatch {
	if !strings.Contains(text, textURLTokenSeparator) {
		return nil
	}
	var matches []TextDLPMatch
	for _, loc := range textURLTokens(text) {
		if ctx.Err() != nil {
			break
		}
		token := text[loc.start:loc.end]
		var targets []dlpTarget
		if parsed, err := url.Parse(token); err == nil {
			targets = urlDLPTargets(parsed, decodes)
		} else {
			// Malformed escapes (e.g. %ZZ in path) make url.Parse fail; retain
			// raw URL and query-concatenation views so malformed syntax cannot
			// disable embedded-URL card enforcement.
			targets = append(targets, dlpTarget{token, dlpViewLabel("url"), ""})
			if _, rest, ok := strings.Cut(token, "?"); ok {
				rawQuery, _, _ := strings.Cut(rest, "#")
				targets = appendQueryConcatTargets(targets, "", rawQuery, decodes)
			}
		}

		for _, target := range targets {
			view := normalize.ForDLP(target.text)
			for _, id := range s.dlpCardPatternIndices {
				p := *s.dlpPatterns[id]
				p.cardURL = true
				var example textByteSpan
				pattern := p.withPublicExamples(view, &example)
				start, end, found := pattern.matchSpanWithDecodes(view, target.text, decodes)
				if example.end > 0 {
					matches = append(matches, p.textDLPFinding(view, "url", example.start, example.end, true))
				}
				if found {
					matches = append(matches, p.textDLPFinding(view, "url", start, end, false))
				}
			}
		}
	}
	return matches
}

// textURLTokens is the sole embedded-URL tokenizer, shared by card, hostname,
// and userinfo scanning. Sentence punctuation is removed only when unbalanced.
func textURLTokens(text string) []textByteSpan {
	var tokens []textByteSpan
	for _, loc := range carddlp.URLSpans(text) {
		tokens = append(tokens, textByteSpan{loc.Start, loc.End})
	}
	return tokens
}
