// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/url"
	"testing"
	"time"
)

// BenchmarkIssuerIDFullCacheListing mints a 512-item listing of new IDs into
// a full ID cache, with and without frozen destinations' pinned proofs mixed in.
func BenchmarkIssuerIDFullCacheListing(b *testing.B) {
	learning, err := url.Parse("https://api.vendor.example/items")
	if err != nil {
		b.Fatal(err)
	}
	frozen, err := url.Parse("https://files.vendor.example/items")
	if err != nil {
		b.Fatal(err)
	}
	id := func(prefix string, n int) string {
		return fmt.Sprintf("2c712604-%s-44e7-a1f5-%012x", prefix, n)
	}
	for _, pinned := range []int{0, 1500, 2900} {
		b.Run(fmt.Sprintf("pinned-%d", pinned), func(b *testing.B) {
			s := newIssuerQueryStore()
			now := time.Time{}
			s.recordSent("reader", learning, nil, nil, true, now)
			s.recordSent("reader", frozen, nil, nil, true, now)
			for i := range pinned {
				s.mintServerID("reader", frozen, id("1370", i), now)
			}
			s.mu.Lock()
			s.freezeIDDestinationLocked(s.idDestinationLocked("reader", frozen), issuerHistoryUnreadBody)
			s.mu.Unlock()
			for i := range issuerCookieMaxEntries - pinned {
				s.mintServerID("reader", learning, id("2480", i), now)
			}
			if s.idCount("reader") != issuerCookieMaxEntries {
				b.Fatalf("fixture cache = %d", s.idCount("reader"))
			}
			next := 0
			b.ReportAllocs()
			for b.Loop() {
				for range 512 {
					s.mintServerID("reader", learning, id("3590", next), now)
					next++
				}
			}
			if s.idCount("reader") != issuerCookieMaxEntries {
				b.Fatalf("cache = %d", s.idCount("reader"))
			}
		})
	}
}
