// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestDLPKeywordsReceiptProjection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "account identifier", Regex: `[0-9]{16}`, Keywords: []string{"account"}}}
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	det := sc.ScanTextForDLPQuiet
	if !det(t.Context(), "3333333333333333").Clean {
		t.Fatal("bare atom unexpectedly qualified")
	}
	rep, err := scanDetail(t, det, mustJSON(t, map[string]any{"account": "3333333333333333"}))
	requireView(t, rep, err, ViewStructured)
	projection, err := testProducer.Project(mustJSON(t, map[string]any{"version": "account", "note": "3333333333333333"}))
	if err != nil {
		t.Fatal(err)
	}
	rep, err = Scan(t.Context(), det, projection)
	if err != nil || !rep.Clean() {
		t.Fatalf("generated field supplied a keyword: %+v %v", rep, err)
	}
	rep, err = scanDetail(t, det, mustJSON(t, map[string]any{"note": "account 3333333333333333"}))
	if err != nil || len(rep.Findings) == 0 || !rep.Findings[0].Contextual {
		t.Fatalf("lost contextual redaction obligation: %+v %v", rep, err)
	}
}
