// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"net/url"
	"strings"
)

// scriptURLReferences observes exact, unescaped URL bytes between quotes. It is
// deliberately not a JavaScript parser: a URL in a comment or inert expression
// still proves that the serving origin possesses those bytes. The caller MUST
// enforce the same-origin boundary. This never proves a computed value or gives
// another origin permission to receive it. Absolute, root-relative and explicit
// dot-relative URLs follow RFC 3986 sections 4.2 and 4.3. Bare module specifiers
// require browser import-map context and are not inferred as resource paths.
func scriptURLReferences(body []byte, limit int) []string {
	if limit <= 0 || len(body) > issuerQueryMaxHTMLBytes {
		return nil
	}
	var relative, other []string
	seen := make(map[string]struct{})
	for i, c := range body {
		if c != '\'' && c != '"' {
			continue
		}
		if i > 0 && body[i-1] == '\\' {
			continue
		}
		// Stop at the next raw quote of this kind. Do not decode escapes or
		// extrapolate a URL from string concatenation. Searching each of the two
		// quote kinds this way visits each intervening span at most twice.
		end := min(len(body), i+issuerCookieMaxPairBytes+2)
		n := bytes.IndexByte(body[i+1:end], c)
		if n < 0 {
			continue
		}
		raw := body[i+1 : i+1+n]
		if len(raw) == 0 || bytes.ContainsAny(raw, "\\\r\n") {
			continue
		}
		value := string(raw)
		if _, exists := seen[value]; exists {
			continue
		}
		ref, err := url.Parse(value)
		dotRelative := strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../")
		if err != nil || (!ref.IsAbs() && raw[0] != '/' && !dotRelative) {
			continue
		}
		// The captured module producer uses dot-relative URLs. Prefer those
		// within the existing response budget without recognizing JavaScript
		// tokens, comments or execution. Every grant still needs the caller's
		// same-origin check; the origin already possesses the literal bytes.
		if dotRelative {
			relative = append(relative, value)
			seen[value] = struct{}{}
			if len(relative) == limit {
				return relative
			}
		} else if len(other) < limit {
			other = append(other, value)
			seen[value] = struct{}{}
		}
	}
	return append(relative, other[:min(len(other), limit-len(relative))]...)
}
