// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// joinedViewCard is a Luhn-valid test card number split into two halves that
// look like ordinary eight-digit record IDs. Neither half is a card on its own.
func joinedViewCard() (string, string) {
	return strings.Repeat("4", 1) + "1111111", strings.Repeat("1", 8)
}

func joinedViewScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0 // isolate DLP from the entropy gate
	sc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	return sc
}

func joinedAllowance(queryIssued, pathIssued bool, seen *[]url.Values) IssuerJoinedViewAllowance {
	return func(_ string, query url.Values) (bool, bool) {
		if seen != nil {
			*seen = append(*seen, query)
		}
		return queryIssued, pathIssued
	}
}

func TestIssuerJoinedViewAllowance(t *testing.T) {
	first, second := joinedViewCard()
	sc := joinedViewScanner(t)
	joined := "https://records.vendor.example/detail?wo=" + first + "&site=" + second

	t.Run("baseline: the joined view blocks the card", func(t *testing.T) {
		got := sc.Scan(context.Background(), joined)
		if got.Allowed || got.Scanner != ScannerDLP || !strings.Contains(got.Reason, "Credit Card Number") {
			t.Fatalf("got %+v, want a Credit Card Number DLP block: the premise of every other case", got)
		}
	})

	t.Run("every value issued: the joined artifact is relieved", func(t *testing.T) {
		var seen []url.Values
		got := sc.Scan(WithIssuerJoinedViewAllowance(context.Background(), joinedAllowance(true, false, &seen)), joined)
		if !got.Allowed {
			t.Fatalf("got %+v, want allowed", got)
		}
		if len(seen) != 1 || seen[0].Get("wo") != first || seen[0].Get("site") != second {
			t.Fatalf("allowance saw %v, want the scanner's own decoded parse", seen)
		}
	})

	t.Run("allowance refuses: still blocked", func(t *testing.T) {
		got := sc.Scan(WithIssuerJoinedViewAllowance(context.Background(), joinedAllowance(false, true, nil)), joined)
		if got.Allowed {
			t.Fatal("a refused allowance relieved the joined view")
		}
	})

	t.Run("a whole card inside one value is never relieved", func(t *testing.T) {
		single := "https://records.vendor.example/detail?wo=" + first + second + "&site=1"
		got := sc.Scan(WithIssuerJoinedViewAllowance(context.Background(), joinedAllowance(true, true, nil)), single)
		if got.Allowed || !strings.Contains(got.Reason, "Credit Card Number") {
			t.Fatalf("got %+v, want the per-value view to block", got)
		}
	})

	t.Run("subsequence across interleaved values is relieved only with evidence", func(t *testing.T) {
		interleaved := "https://records.vendor.example/detail?a=" + first + "&pad=x&b=" + second + "&tail=y"
		if got := sc.Scan(context.Background(), interleaved); got.Allowed {
			t.Fatal("premise: the subsequence search should reconstruct the card")
		}
		got := sc.Scan(WithIssuerJoinedViewAllowance(context.Background(), joinedAllowance(true, false, nil)), interleaved)
		if !got.Allowed {
			t.Fatalf("got %+v, want allowed", got)
		}
	})

	t.Run("an unparseable query gets no relief", func(t *testing.T) {
		var seen []url.Values
		semicolon := "https://records.vendor.example/detail?wo=" + first + ";x=1&site=" + second
		baseline := sc.Scan(context.Background(), semicolon)
		got := sc.Scan(WithIssuerJoinedViewAllowance(context.Background(), joinedAllowance(true, true, &seen)), semicolon)
		if got.Allowed != baseline.Allowed || got.Reason != baseline.Reason {
			t.Fatalf("allowance changed the verdict for a query the standard parser rejects: %+v vs %+v", got, baseline)
		}
		if len(seen) != 0 {
			t.Fatal("the allowance was consulted for a query that does not parse")
		}
	})

	t.Run("path-to-query seam needs the path issued too", func(t *testing.T) {
		seam := "https://records.vendor.example/" + first + "?a=" + second + "&b="
		if got := sc.Scan(context.Background(), seam); got.Allowed {
			t.Fatal("premise: the seam view should reconstruct the card")
		}
		if got := sc.Scan(WithIssuerJoinedViewAllowance(context.Background(), joinedAllowance(true, false, nil)), seam); got.Allowed {
			t.Fatal("seam relieved although the path was not issued")
		}
		if got := sc.Scan(WithIssuerJoinedViewAllowance(context.Background(), joinedAllowance(true, true, nil)), seam); !got.Allowed {
			t.Fatalf("got %+v, want allowed when path and every value were issued", got)
		}
	})

	t.Run("credential-shaped value in an issued query still blocks", func(t *testing.T) {
		key := "AKIA" + "IOSFODNN7" + "EXAMPLE"
		got := sc.Scan(WithIssuerJoinedViewAllowance(context.Background(), joinedAllowance(true, true, nil)),
			"https://records.vendor.example/detail?k="+key+"&site="+second)
		if got.Allowed {
			t.Fatal("an issued allowance relieved a per-value credential match")
		}
	})

	t.Run("no query: allowance never consulted", func(t *testing.T) {
		var seen []url.Values
		_ = sc.Scan(WithIssuerJoinedViewAllowance(context.Background(), joinedAllowance(true, true, &seen)), "https://records.vendor.example/detail")
		if len(seen) != 0 {
			t.Fatal("allowance consulted without a query")
		}
	})
}
