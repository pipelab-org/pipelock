// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Fixed HMAC-SHA256 tuples preserve the store's byte-length-prefixed encoding,
// including field boundaries and raw bytes, across repeated MAC reuse.
func TestIssuerDigestFieldsEncoding(t *testing.T) {
	s := newTestServerIDStore(t)
	for i := range s.key {
		s.key[i] = byte(i)
	}
	mac := hmac.New(sha256.New, s.key[:])
	for _, tc := range []struct {
		fields []string
		want   string
	}{
		{[]string{"sent_host", "api.vendor.example", "object-first-identifier"}, "9237900c329a90b9f112a3745dbaf634566e5ce299620c3a50f0bd4fab9498e8"},
		{[]string{"sent_host", "api.vendor.example", "second,identifier"}, "7ec5ca824d842e43c768da2eda1cead87a5bc23edd6efcb887e1616b58058be2"},
		{[]string{"ab", "c"}, "17eca1f3cf4e1f92cd415f54de5121e367cbc209edff96da287c5cd432cf9a46"},
		{[]string{"a", "bc"}, "3bddf4bc854ae05364f6353a7ec018de74fb1fe6bb599207f172368d9490b9dd"},
		{[]string{"raw", string([]byte{0xff, 0})}, "02e4e43c7418f39515f339ecd8f986438898333d265593fd5a0966e75c677bc3"},
	} {
		got := issuerDigestFields(mac, tc.fields...)
		if hex.EncodeToString(got[:]) != tc.want || got != s.digestFields(tc.fields...) {
			t.Fatalf("tuple %q changed encoding", tc.fields)
		}
	}
}

func TestCompositeIDOrdinaryListWorkloads(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	for _, size := range []int{2, 16, 36} {
		for _, count := range []int{100, 400, 1000} {
			t.Run(fmt.Sprintf("field-%d/items-%d", size, count), func(t *testing.T) {
				fields := make([]string, count)
				for i := range fields {
					fields[i] = strings.Repeat("x", size)
				}
				s := newTestServerIDStore(t)
				s.recordSent("reader", origin, nil, []byte("ids="+strings.Join(fields, ",")), true, time.Now())
				t.Logf("body_bytes=%d history_entries=%d history_unreadable=%v", count*(size+1)+3, s.sentEntries, s.sentUnreadable["reader"])
				if s.sentUnreadable["reader"] != issuerHistoryComplete {
					t.Fatal("ordinary list exhausted per-request history budget")
				}
			})
		}
	}
}

func TestShortFieldsDoNotExpandIDHistory(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	fields := make([]string, issuerSentMaxTokensPerRequest+2)
	for i := range fields {
		fields[i] = fmt.Sprintf("%04x", i)
	}
	s := newTestServerIDStore(t)
	s.recordSent("reader", origin, nil, []byte(strings.Join(fields, ",")), true, time.Now())
	if s.sentUnreadable["reader"] != issuerHistoryComplete || s.sentEntries != 0 {
		t.Fatal("short fields added history or consumed the input-token budget")
	}
	s.mintServerID("reader", origin, compositeSiteID, time.Now())
	if !s.serverIDIssued("reader", origin, compositeSiteID) {
		t.Fatal("short fields prevented a subsequent genuinely introduced ID")
	}
}

func BenchmarkIssuerSentListWorkload(b *testing.B) {
	origin, err := url.Parse("https://api.vendor.example/items")
	if err != nil {
		b.Fatal(err)
	}
	for _, unique := range []bool{false, true} {
		for _, count := range []int{100, 400, 1000} {
			fields := make([]string, count)
			for i := range fields {
				id := 0
				if unique {
					id = i
				}
				fields[i] = fmt.Sprintf("2c712604-1370-44e7-a1f5-%012x", id)
			}
			body := "ids=" + strings.Join(fields, ",")
			b.Run(fmt.Sprintf("unique-%t/items-%d", unique, count), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(body)))
				for b.Loop() {
					s := newIssuerQueryStore()
					s.recordSent("reader", origin, nil, []byte(body), true, time.Time{})
				}
			})
		}
	}
}
