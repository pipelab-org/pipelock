// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package carddlp

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// URLPattern is the supported scheme-prefixed text URL grammar. Bare dotted
// prose is intentionally excluded. Keep every consumer on this one grammar.
const URLPattern = `(?i)\b(?:https?|wss?|s?ftp|ftps|file)://[^\s"'<>\\]+`

var (
	// Both probes derive from the sole URL grammar. The first only locates
	// a scheme ending at a known delimiter; the second keeps the full match
	// anchored so a malformed candidate cannot rescan the remaining body.
	urlSchemePrefixRE = regexp.MustCompile(strings.SplitN(URLPattern, "://", 2)[0] + "://$")
	// The prefix probe already checked the original word boundary. Repeating
	// it after slicing would change Unicode simple-fold schemes such as ſftp.
	urlTokenStartRE = regexp.MustCompile(`\A(?:` + strings.Replace(URLPattern, `\b`, "", 1) + `)`)
)

// https is the longest scheme in URLPattern. The grammar parity test checks
// this bound independently, including future edits to that grammar.
const maxURLSchemeRunes = len("https")

// URLSpan locates an embedded URL in the supplied text, using byte offsets.
type URLSpan struct{ Start, End int }

// URLSpans extracts URLs, dropping sentence punctuation and unmatched closers.
func URLSpans(text string) []URLSpan {
	var spans []URLSpan
	for at := 0; at < len(text); {
		next := strings.Index(text[at:], "://")
		if next < 0 {
			break
		}
		colon := at + next
		// Keep a full rune of preceding context so the probe cannot invent a
		// word boundary at the beginning of its bounded window.
		probeStart := max(0, colon-(maxURLSchemeRunes+1)*utf8.UTFMax)
		loc := urlSchemePrefixRE.FindStringIndex(text[probeStart : colon+3])
		if loc == nil {
			at = colon + 1
			continue
		}
		start := probeStart + loc[0]
		full := urlTokenStartRE.FindStringIndex(text[start:])
		if full == nil {
			at = colon + 1
			continue
		}
		end := start + full[1]
		at = end
		token := text[start:end]
		balance := map[byte]int{
			')': strings.Count(token, ")") - strings.Count(token, "("),
			']': strings.Count(token, "]") - strings.Count(token, "["),
			'}': strings.Count(token, "}") - strings.Count(token, "{"),
		}
		for end > start {
			last := text[end-1]
			if strings.ContainsRune(".,;:", rune(last)) {
				end--
				continue
			}
			if balance[last] > 0 {
				balance[last]--
				end--
				continue
			}
			break
		}
		spans = append(spans, URLSpan{start, end})
	}
	return spans
}

func visitTextView(text string, yield func(Candidate) bool) bool {
	if Visit(text, false, yield) {
		return true
	}
	if !strings.Contains(text, "://") {
		return false
	}
	for _, span := range URLSpans(text) {
		token := text[span.Start:span.End]
		if Visit(token, true, func(c Candidate) bool {
			c.Start += span.Start
			c.End += span.Start
			return yield(c)
		}) {
			return true
		}
		parsed, err := url.Parse(token)
		if err != nil {
			if _, rest, ok := strings.Cut(token, "?"); ok {
				rawQuery, _, _ := strings.Cut(rest, "#")
				if query := decodedRawQueryValues(rawQuery); Visit(query, true, func(c Candidate) bool {
					c.Start, c.End = span.Start, span.End
					return yield(c)
				}) {
					return true
				}
			}
			continue
		}
		// RFC 3986 percent decoding and URL-ordered query values preserve the
		// existing URL reconstruction contract. Reconstructed spans replace the
		// complete URL because their source bytes may be discontiguous.
		views := []string{parsed.Path, parsed.Fragment, decodedRawQueryValues(parsed.RawQuery)}
		if parsed.User != nil {
			views = append(views, parsed.User.Username())
			if pass, ok := parsed.User.Password(); ok {
				views = append(views, pass)
			}
		}
		for _, view := range views {
			if Visit(view, true, func(c Candidate) bool {
				c.Start, c.End = span.Start, span.End
				return yield(c)
			}) {
				return true
			}
		}
	}
	return false
}

func decodedRawQueryValues(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	var query strings.Builder
	for _, pair := range strings.Split(rawQuery, "&") {
		key, value, hasEq := strings.Cut(pair, "=")
		if !hasEq {
			value = key
		}
		decoded, err := url.QueryUnescape(value)
		if err == nil {
			query.WriteString(decoded)
		} else {
			query.WriteString(value)
		}
	}
	return query.String()
}
