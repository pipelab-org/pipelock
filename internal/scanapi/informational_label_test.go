// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0
package scanapi

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestInformationalDLPLabel(t *testing.T) {
	got := dlpFindings(scanner.TextDLPResult{Clean: true, InformationalMatches: []scanner.TextDLPMatch{{PatternName: "Custom token", Warn: true}}}, nil)
	if len(got) != 1 || strings.Contains(strings.ToLower(got[0].Message), "card") || !strings.Contains(got[0].Message, "Custom token") {
		t.Fatalf("incorrect informational label: %+v", got)
	}
}
