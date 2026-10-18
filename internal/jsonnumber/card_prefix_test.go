// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestAcceptedCardEnd(t *testing.T) {
	card := cardtest.Number()
	spaced := cardtest.Grouped(card, " ")
	dashed := cardtest.Grouped(card, "-")
	invalid := card[:15] + "2"
	for _, tt := range []struct {
		name string
		hit  string
		want string // accepted candidate; "" means none
	}{
		{"complete hit wins", card, card},
		{"complete grouped hit wins", spaced, spaced},
		{"space then digit", card + " 1", card},
		{"space then two digits", card + " 12", card},
		{"dash then digit", card + "-3", card},
		{"grouped then digit", spaced + " 1", spaced},
		{"dashed then dash digit", dashed + "-3", dashed},
		{"three trailing digits", card + " 123", card},
		{"invalid checksum before digit", invalid + " 1", ""},
		{"contiguous overlong group is never cut", card + "2", ""},
		{"prefix below the rule floor", card[:12] + " 123", ""},
		{"non separator byte", card + "/1", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			end, ok := AcceptedCardEnd(tt.hit, func(end int) bool { return ValidCardNumber(tt.hit[:end]) })
			got := ""
			if ok {
				got = tt.hit[:end]
			}
			if got != tt.want {
				t.Fatalf("accepted %q, want %q", got, tt.want)
			}
		})
	}
}

// Longest first: a 19-digit Visa that validates whole is never cut back to
// its 16-digit prefix, and every retried candidate is a full shipped match.
func TestAcceptedCardEndLongestFirstAndWholeMatch(t *testing.T) {
	visa19 := cardtest.Issuer("4111", 19)
	hit := visa19[:16] + " " + visa19[16:]
	var tried []string
	end, ok := AcceptedCardEnd(hit, func(end int) bool {
		tried = append(tried, hit[:end])
		return ValidCardNumber(hit[:end])
	})
	if !ok || hit[:end] != hit || len(tried) != 1 {
		t.Fatalf("whole 19-digit card not preferred: ok=%v tried=%q", ok, tried)
	}
	whole := regexp.MustCompile(`^(?:` + ShippedCardPattern + `)$`)
	padded := cardtest.Grouped(cardtest.Number(), " ") + " 1 2"
	tried = nil
	AcceptedCardEnd(padded, func(end int) bool {
		tried = append(tried, padded[:end])
		return false
	})
	if len(tried) < 2 || len(tried[0]) < len(tried[len(tried)-1]) {
		t.Fatalf("retries not longest first: %q", tried)
	}
	for _, candidate := range tried {
		if !whole.MatchString(candidate) {
			t.Fatalf("retried candidate %q is not a complete shipped-rule match", candidate)
		}
		if strings.HasSuffix(candidate, " ") || strings.HasSuffix(candidate, "-") {
			t.Fatalf("retried candidate %q ends on a separator", candidate)
		}
	}
}

func TestIsShippedCardPattern(t *testing.T) {
	if !IsShippedCardPattern(ShippedCardPattern) || IsShippedCardPattern(`\b\d{4}(?:[ ]?\d){11,15}\b`) {
		t.Fatal("shipped card rule identity is wrong")
	}
}
