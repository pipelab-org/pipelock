// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package carddlp

import (
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestURLSpans(t *testing.T) {
	for _, scheme := range []string{"http", "HTTPS", "ws", "wss", "ftp", "ftps", "sftp", "file"} {
		for _, tail := range []string{"/path", "/(path)", "/[path]", "/{path}"} {
			want := scheme + "://api.vendor.example" + tail
			text := "see (" + want + ").,;:]}"
			spans := URLSpans(text)
			if len(spans) != 1 || text[spans[0].Start:spans[0].End] != want {
				t.Fatalf("token span changed for %q: %+v", text, spans)
			}
		}
	}
	if spans := URLSpans("not a scheme://host or api.vendor.example"); len(spans) != 0 {
		t.Fatal("treated ordinary text as a URL", spans)
	}
}

func TestURLCardTextSpans(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, token := range []string{
		"https://api.vendor.example/path/" + pan[:4] + "." + pan[4:],
		"https://a." + pan[:4] + "." + pan[4:] + ".vendor.example/",
		"https://api.vendor.example/?a=" + pan[:8] + "&b=" + pan[8:],
		"https://api.vendor.example/" + url.PathEscape(pan[:4]+"/"+pan[4:]),
		"https://api.vendor.example/#" + pan[:4] + "%2F" + pan[4:],
		"https://api.vendor.example/" + pan[:4] + "\u200b." + pan[4:],
		"https://api.vendor.example/?" + pan[:4] + "%3" + pan[4:5] + pan[5:],
		"https://" + pan[:4] + "%3" + pan[4:5] + pan[5:] + "@api.vendor.example/",
		"https://user:" + pan[:4] + "%3" + pan[4:5] + pan[5:] + "@api.vendor.example/",
		"https://api.vendor.example/%ZZ/?a=" + pan[:8] + "&b=" + pan[8:],
		"https://api.vendor.example/" + pan[:4] + "%E2%80%8B" + pan[4:],
		"https://api.vendor.example/#" + pan[:4] + "%E2%80%8B" + pan[4:],
		"https://api.vendor.example/?a=" + pan[:4] + "%E2%80%8B" + pan[4:],
		"https://api.vendor.example/%ZZ/?a=" + pan[:4] + "%E2%80%8B" + pan[4:],
		"https://api.vendor.example/?a=%34" + pan[1:] + "&b=%34" + pan[1:],
		"https://api.vendor.example/%ZZ/?a=%34" + pan[1:] + "&b=%34" + pan[1:],
	} {
		text := "see (" + token + ")."
		for _, stop := range []bool{false, true} {
			found := false
			stopped := VisitText(text, func(c Candidate) bool {
				found = true
				if c.Digits != pan || c.Start < strings.Index(text, token) || c.End > strings.Index(text, token)+len(token) {
					t.Fatalf("incorrect original URL span: %+v", c)
				}
				return stop
			})
			if !found || stopped != stop {
				t.Fatalf("URL card missing from %q", text)
			}
		}
	}
	for _, text := range []string{"https://api.vendor.example/path", "https://api.vendor.example/?a=%XX", "http://[invalid]/path", "４not a card", "https://api.vendor.example/１２３４"} {
		if VisitText(text, func(Candidate) bool { return true }) {
			t.Fatalf("clean URL became a card: %q", text)
		}
	}
}

func TestURLCardIndependentQueryValues(t *testing.T) {
	first, second := cardtest.Issuer("4019", 16), cardtest.Issuer("5191", 16)
	token := "https://api.vendor.example/?a=%34" + first[1:] + "&b=%35" + second[1:]
	seen := map[string]bool{}
	VisitText(token, func(c Candidate) bool {
		if c.Start != 0 || c.End != len(token) {
			t.Fatalf("decoded span must replace URL: %+v", c)
		}
		seen[c.Digits] = true
		return false
	})
	if !seen[first] || !seen[second] {
		t.Fatalf("independent query values lost: %v", seen)
	}
}

func TestURLCardIndependentQueryNames(t *testing.T) {
	first, second := cardtest.Issuer("4019", 16), cardtest.Issuer("5191", 16)
	for _, suffix := range []string{"=x", "=x&b=%35" + second[1:], ""} {
		token := "https://api.vendor.example/?%34" + first[1:] + suffix
		seen := map[string]bool{}
		VisitText(token, func(c Candidate) bool {
			if c.Start != 0 || c.End != len(token) {
				t.Fatalf("decoded name span: %+v", c)
			}
			seen[c.Digits] = true
			return false
		})
		if !seen[first] || strings.Contains(suffix, "&") && !seen[second] {
			t.Errorf("query names missing for %q: %v", token, seen)
		}
	}
}

func TestDecodedQuerySingleTokenVisitedOnce(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, suffix := range []string{"", "&note=safe"} {
		count := 0
		visitDecodedQueryValues("%34"+pan[1:]+suffix, func(c Candidate) bool {
			if c.Digits == pan {
				count++
			}
			return false
		})
		if count != 1 {
			t.Fatalf("single token visited %d times, suffix=%q", count, suffix)
		}
	}
}

func TestCardMixedControlContext(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, sep := range []string{"\t", "\r", "\n", "\r\n"} {
		split := pan[:4] + sep + pan[4:]
		for _, text := range []string{"0." + split, split + "-99", pan[:4] + sep + pan[4:8] + " " + pan[8:]} {
			found := false
			VisitText(text, func(c Candidate) bool { found = found || c.Digits == pan; return false })
			if !found {
				t.Errorf("mixed presentation missing: %q", text)
			}
		}
		if VisitText(split, func(Candidate) bool { return true }) {
			t.Errorf("pure control join detected: %q", split)
		}
		token := "https://api.vendor.example/?v=" + url.QueryEscape(split)
		if !VisitText(token, func(c Candidate) bool { return c.Digits == pan }) {
			t.Errorf("URL control join missing: %q", token)
		}
	}
}
