// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDLPKeywordHTMLPresence(t *testing.T) {
	sc := keywordScanner(t, []string{"lookup"}, 50)
	t.Cleanup(sc.Close)
	// Exercise the ordinary decoder independently of terminal production.
	sc.reassemblyPlan = nil
	body := "&lt;p&gt;" + hex.EncodeToString([]byte(strings.Repeat(keywordNumber, 1000))) + "&lt;/p&gt;"
	result := sc.ScanTextForDLP(t.Context(), body)
	if !result.Clean || len(result.Matches) != 0 {
		t.Fatalf("unlabeled HTML-decoded record: %+v", result.Matches)
	}
	body = "&lt;p&gt;" + hex.EncodeToString([]byte("lookup "+keywordNumber)) + "&lt;/p&gt;"
	result = sc.ScanTextForDLP(t.Context(), body)
	if !keywordFound(result) || HasInspectionLimit(result.Matches) {
		t.Fatalf("labeled HTML-decoded record: %+v", result.Matches)
	}
}

func TestDLPKeywordPresenceNormalization(t *testing.T) {
	// Mark removal leaves a Cyrillic base letter; the next normalization
	// pass would map it to ASCII. Presence must use the main keyword unit.
	label := "\u0401xx"
	once := config.DLPKeywordContext(label)
	if once == config.DLPKeywordContext(once) {
		t.Fatal("fixture did not change on a second pass")
	}
	gate, err := (config.DLPPattern{Name: keywordPattern, Regex: `[0-9]{16}`, Keywords: []string{"exx"}}).CompileKeywords()
	if err != nil {
		t.Fatal(err)
	}
	context := keywordCandidateContext{source: once}
	if !context.keywordPossible(gate, once, false) {
		t.Fatal("raw source presence was treated as an already normalized lane")
	}
	sc := keywordScanner(t, []string{label}, 50)
	t.Cleanup(sc.Close)
	result := sc.ScanTextForDLP(t.Context(), label+" "+keywordNumber)
	if !keywordFound(result) {
		t.Fatalf("keyword unit normalized twice: %+v", result.Matches)
	}
}
