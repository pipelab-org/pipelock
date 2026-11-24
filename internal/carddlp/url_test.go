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
