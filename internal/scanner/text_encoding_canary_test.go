// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "testing"

func TestTextEncodingCanaryAttributionRetainsPatternFindings(t *testing.T) {
	s := testCanaryScanner()
	t.Cleanup(s.Close)
	carrier := decimalCharacterCodes(testCanaryValue(), " ") + "\n" + "xoxb-" + "1234567890abcdef"
	result := s.ScanTextForDLP(t.Context(), carrier)
	if result.Clean || len(result.Matches) == 0 || result.Matches[0].PatternName != "Canary Token ("+testCanaryName+")" {
		t.Fatalf("configured canary did not lead attribution: %+v", result)
	}
	foundPattern := false
	for _, m := range result.Matches {
		if m.PatternName == "Slack Token" {
			foundPattern = true
		}
	}
	if !foundPattern {
		t.Fatalf("independent pattern finding missing: %+v", result)
	}
}
