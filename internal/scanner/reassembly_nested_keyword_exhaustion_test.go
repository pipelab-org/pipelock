// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyNestedKeywordExhaustion(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Labeled marker", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh, Keywords: []string{"lookup"}}}
	sc := MustNew(cfg)
	defer sc.Close()
	for _, escaped := range []string{"&#77;&#65;&#82;&#75;1234", `\u004d\u0041\u0052\u004b1234`} {
		for _, inbound := range []bool{false, true} {
			body := hex.EncodeToString([]byte(escaped))
			memo := &decodingMemo{keywordMode: true, keywordInput: body, keywordUnit: body, keywordBudget: &keywordWorkBudget{used: maxDecodeTotalBytes}, reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true, reassemblyInbound: inbound}
			defer memo.releaseProjection()
			memo.reassemblyObserve(body)
			result := finishAssembled(TextDLPResult{Clean: true}, memo)
			if inbound {
				if !slices.Contains(matchNames(result.Matches), PartialEncodedContentPattern) || !result.Clean || HasInspectionLimit(result.Matches) {
					t.Errorf("inbound lost partial warning: %+v", result)
				}
			} else if !HasInspectionLimit(result.Matches) {
				t.Errorf("outbound lost refusal: %+v", result)
			}
		}
	}
}
