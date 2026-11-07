// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestReassemblyKeywordProjectionContext(t *testing.T) {
	sc := keywordScanner(t, []string{"~~~"}, 10)
	defer sc.Close()
	body := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5000) + keywordNumber)))
	source := "https://" + body + strings.Repeat("!", 20) + ":" + body + "~~~@api.vendor.example/"
	if result := sc.ScanTextForDLP(t.Context(), source); !keywordFound(result) || HasInspectionLimit(result.Matches) {
		t.Fatalf("qualified userinfo context lost: %+v", result)
	}
	windowScanner := keywordScanner(t, []string{"account"}, 50)
	defer windowScanner.Close()
	for _, enc := range reassemblyEncodings(keywordNumber) {
		result := windowScanner.ScanTextForDLP(t.Context(), "account"+strings.Repeat(" ", 100)+enc.text)
		if keywordFound(result) || HasInspectionLimit(result.Matches) {
			t.Errorf("%s: source keyword window changed: %+v", enc.name, result)
		}
	}
}
