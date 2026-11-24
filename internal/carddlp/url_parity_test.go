// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package carddlp

import (
	"reflect"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

var urlTokenRE = regexp.MustCompile(URLPattern)

func TestURLSpansGrammarParity(t *testing.T) {
	cases := []string{"", "https://", "https:// ", "ahttps://host.example", "ahttps://bad/http://good.example", "http://\vbody", "\xffhttp://host.example", strings.Repeat("a:// ", 4000) + "https://good.example/end"}
	for value := range 256 {
		b := string([]byte{byte(value)})
		cases = append(cases, b+"https://host.example/", "https://"+b+"body", "http:// "+b+"https://next.example/")
	}
	atoms := []string{"x", " ", "https://", "ahttps://", "http:// ", "ſftp://", "host.example/", ").", "http://nested.example/", "\n"}
	for _, a := range atoms {
		for _, b := range atoms {
			for _, c := range atoms {
				cases = append(cases, a+b+c)
			}
		}
	}
	for _, scheme := range []string{"http", "https", "ws", "wss", "ftp", "sftp", "ftps", "file", "HTTP", "hTtPs", "httpſ", "ſftp", "wſſ"} {
		for _, before := range []string{"", "x", "_", "7", "/", " ", "é", strings.Repeat("p", 40) + " "} {
			for _, tail := range []string{"host.example/a?x=1&y=2", "host.example/a).", "host.example/(a)", "host.example/{a}", "host.example/a}.", "host.example/a]. http://next.example/", "host.example/a\n", "host.example/http://nested.example"} {
				cases = append(cases, before+scheme+"://"+tail)
			}
		}
	}
	for _, text := range cases {
		got, want := URLSpans(text), referenceURLSpans(text)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("URL grammar changed for %q: got %v want %v", text, got, want)
		}
	}
}

func TestURLSchemeProbeBound(t *testing.T) {
	tree, err := syntax.Parse(urlSchemePrefixRE.String(), syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	var width func(*syntax.Regexp) int
	width = func(r *syntax.Regexp) int {
		switch r.Op {
		case syntax.OpLiteral:
			return len(r.Rune)
		case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
			return 1
		case syntax.OpCapture, syntax.OpQuest:
			return width(r.Sub[0])
		case syntax.OpConcat:
			n := 0
			for _, child := range r.Sub {
				n += width(child)
			}
			return n
		case syntax.OpAlternate:
			n := 0
			for _, child := range r.Sub {
				n = max(n, width(child))
			}
			return n
		case syntax.OpRepeat:
			if r.Max < 0 {
				t.Fatal("unbounded scheme prefix")
			}
			return r.Max * width(r.Sub[0])
		case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
			return 0
		default:
			t.Fatalf("unsupported scheme grammar operation %v", r.Op)
			return 0
		}
	}
	if n := width(tree); n > maxURLSchemeRunes+len("://") {
		t.Fatalf("URL grammar needs %d scheme runes; update the probe bound", n-len("://"))
	}
}

func referenceURLSpans(text string) []URLSpan {
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
