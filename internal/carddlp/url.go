// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package carddlp

import (
	"net/url"
	"regexp"
	"strings"
)

// URLPattern is the supported scheme-prefixed text URL grammar. Bare dotted
// prose is intentionally excluded. Keep every consumer on this one grammar.
const URLPattern = `(?i)\b(?:https?|wss?|s?ftp|ftps|file)://[^\s"'<>\\]+`

var urlTokenRE = regexp.MustCompile(URLPattern)

// URLSpan locates an embedded URL in the supplied text, using byte offsets.
type URLSpan struct{ Start, End int }

// URLSpans extracts URLs, dropping sentence punctuation and unmatched closers.
func URLSpans(text string) []URLSpan {
	var spans []URLSpan
	for _, loc := range urlTokenRE.FindAllStringIndex(text, -1) {
		end := loc[1]
		token := text[loc[0]:end]
		balance := map[byte]int{
			')': strings.Count(token, ")") - strings.Count(token, "("),
			']': strings.Count(token, "]") - strings.Count(token, "["),
			'}': strings.Count(token, "}") - strings.Count(token, "{"),
		}
		for end > loc[0] {
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
		spans = append(spans, URLSpan{loc[0], end})
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
			continue
		}
		// RFC 3986 percent decoding and URL-ordered query values preserve the
		// existing URL reconstruction contract. Reconstructed spans replace the
		// complete URL because their source bytes may be discontiguous.
		var query strings.Builder
		for _, pair := range strings.Split(parsed.RawQuery, "&") {
			_, value, _ := strings.Cut(pair, "=")
			decoded, err := url.QueryUnescape(value)
			if err == nil {
				query.WriteString(decoded)
			}
		}
		for _, view := range []string{parsed.Path, parsed.Fragment, query.String()} {
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
