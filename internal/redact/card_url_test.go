// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestCardURLPresentation(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	m := NewDefaultMatcher()
	for _, text := range []string{
		"https://api.vendor.example/path/" + pan[:4] + "." + pan[4:],
		"https://api.vendor.example/?a=" + pan[:8] + "&b=" + pan[8:],
		"https://a." + pan[:4] + "." + pan[4:] + ".vendor.example/",
		"https://api.vendor.example/?" + pan[:4] + "%3" + pan[4:5] + pan[5:],
		"https://" + pan[:4] + "%3" + pan[4:5] + pan[5:] + "@api.vendor.example/",
		"https://api.vendor.example/%ZZ/?a=" + pan[:8] + "&b=" + pan[8:],
	} {
		found := false
		for _, match := range m.Scan(text) {
			found = found || match.Class == ClassCreditCard
		}
		if !found {
			t.Fatalf("URL card was not redacted: %s", text)
		}
	}
	for _, text := range []string{pan[:4] + "." + pan[4:], pan[:8] + "\t" + pan[8:], strings.Repeat("4242", 4)} {
		for _, match := range m.Scan(text) {
			if match.Class == ClassCreditCard {
				t.Fatalf("non-enforcing body matched: %s", text)
			}
		}
	}
}

func TestLegacyCardRedactionUnion(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	invalid := pan[:15] + string('0'+(pan[15]-'0'+1)%10)
	m := NewDefaultMatcher()
	for _, value := range []string{invalid, cardtest.Grouped(invalid, " "), invalid[:8] + "-" + invalid[8:], invalid[:12] + " " + invalid[12:], pan[:6] + " - " + pan[6:], pan[:4] + "   " + pan[4:]} {
		if len(m.Scan(value)) == 0 {
			t.Errorf("legacy shape lost: %q", value)
		}
	}
}
