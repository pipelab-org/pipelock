// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"strings"
	"testing"
)

func TestDLPKeywordsQueryKeyContext(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)

	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"?account=33333333&part=33333333", true},
		{"?reference=33333333&part=33333333", false},
		{"?account" + strings.Repeat("x", 100) + "=33333333&part=33333333", false},
		{"?first=33333333&account=33333333", false},
	} {
		u, err := url.Parse("https://api.vendor.example/" + tc.query)
		if err != nil {
			t.Fatal(err)
		}
		result, _ := sc.checkDLP(u)
		if got := strings.Contains(result.Reason, keywordPattern); got != tc.want {
			t.Fatalf("query=%q finding=%v want=%v: %+v", tc.query, got, tc.want, result)
		}
	}
}
