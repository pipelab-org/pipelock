// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestDLPKeywordsReassemblyReceiptProjection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Labeled record", Regex: `[0-9]{16}`, Keywords: []string{"lookup"}}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, label := range []string{"lookup ", ""} {
		encoded := hex.EncodeToString([]byte(strings.Repeat("x", 5000) + label + "3333333333333333"))
		body := strings.Join(strings.Split(encoded, ""), "!")
		report, err := scanDetail(t, sc.ScanTextForDLPQuiet, mustJSON(t, map[string]any{"note": body}))
		if err != nil {
			t.Fatal(err)
		}
		if label == "" {
			if !report.Clean() {
				t.Fatal("unlabeled lane acquired a receipt finding")
			}
		} else if len(report.Findings) == 0 || !report.Findings[0].Contextual {
			t.Fatal("terminal finding lost the receipt redaction obligation")
		}
	}
}
