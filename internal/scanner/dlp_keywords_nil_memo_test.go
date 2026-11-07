// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestDLPKeywordsNilMemo(t *testing.T) {
	sc := keywordScanner(t, []string{"account"}, 50)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"unlabeled", keywordNumber, false},
		{"labeled", "account " + keywordNumber, true},
		{"encoded", "account " + base64.StdEncoding.EncodeToString([]byte(keywordNumber)), true},
	} {
		t.Run("text/"+tc.name, func(t *testing.T) {
			result := sc.scanTextForDLPWithDecodes(t.Context(), tc.text, textDLPOptions{scanSecretLeak: true}, nil)
			if got := keywordFound(result); got != tc.want {
				t.Fatalf("finding=%v want=%v: %+v", got, tc.want, result)
			}
		})
		t.Run("url/"+tc.name, func(t *testing.T) {
			u, err := url.Parse("https://api.vendor.example/?value=" + url.QueryEscape(tc.text))
			if err != nil {
				t.Fatal(err)
			}
			result, _ := sc.checkDLPWithDecodes(u, nil)
			if got := strings.Contains(result.Reason, keywordPattern); got != tc.want {
				t.Fatalf("finding=%v want=%v: %+v", got, tc.want, result)
			}
		})
	}
}
