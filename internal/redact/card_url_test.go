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
