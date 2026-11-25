// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

func TestOfflineCardURLViews(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	re := regexp.MustCompile(jsonnumber.ShippedCardPattern)
	for _, text := range []string{
		"https://api.vendor.example/path/" + pan[:4] + "." + pan[4:],
		"https://api.vendor.example/?a=" + pan[:8] + "&b=" + pan[8:],
	} {
		if !ValidatedPatternMatches(text, re, validateLuhn, true, false) {
			t.Fatalf("offline URL lost card enforcement: %s", text)
		}
	}
}
