// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordsOverlappingSourceOccurrences(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = []config.DLPPattern{{Name: keywordPattern, Regex: `abababab`, Keywords: []string{"account"}, KeywordWindow: new(8)}}
	sc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	u, err := url.Parse("https://api.vendor.example/?61626162=61626162=61626162&account")
	if err != nil {
		t.Fatal(err)
	}
	result, _ := sc.checkDLP(u)
	if !strings.Contains(result.Reason, keywordPattern) {
		t.Fatalf("overlapping source did not qualify: %+v", result)
	}
}
