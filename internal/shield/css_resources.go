// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shield

import "strings"

// CSSResourceURLs returns literal url() and @import references using the existing
// CSS Syntax Level 3 lexer. It does not load resources or confer trust on their
// destinations. Oversize input or a bad lexer token returns no references.
// A non-nil accept filters references before they spend the output limit.
// It must have no externally visible effects: a later bad token discards all.
func CSSResourceURLs(body string, limit int, accept func(string) bool) []string {
	if limit <= 0 || len(body) > maxCSSStyleBytes {
		return nil
	}
	l := cssLexerFor(body)
	var out []string
	var pending string
	importString, urlString, urlClose := false, false, false
	for {
		t := l.token()
		if t.malformed || l.bad {
			return nil
		}
		if t.kind == 0 {
			return out
		}
		if t.kind == cssSpace {
			continue
		}
		value := ""
		switch {
		case t.kind == cssURL:
			value = strings.TrimSuffix(strings.TrimPrefix(t.value, "url("), ")")
		case t.kind == cssString && (importString || urlString):
			if len(t.value) >= 2 {
				if urlString {
					pending, urlClose = t.value[1:len(t.value)-1], true
				} else {
					value = t.value[1 : len(t.value)-1]
				}
			}
		case t.kind == ')' && urlClose:
			value = pending
		}
		if value != "" && !strings.HasPrefix(value, "#") && len(out) < limit && (accept == nil || accept(value)) {
			out = append(out, value)
		}
		if t.kind != cssString || !urlString {
			pending, urlClose = "", false
		}
		importString = t.kind == cssAt && strings.EqualFold(t.value, "@import")
		urlString = t.kind == cssFunction && strings.EqualFold(t.value, "url")
	}
}
