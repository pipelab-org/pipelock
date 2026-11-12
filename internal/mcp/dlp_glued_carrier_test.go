// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestScanRequestGluedBoundaryAndByteList(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	anthropic := "sk-" + "ant-" + "api03-" + strings.Repeat("Ab3dE6gH", 11) + "-xY" + "AA"
	cases := []struct {
		name, arg, pattern string
		want               bool
	}{
		{name: "glued anthropic", arg: "x" + anthropic, pattern: "Anthropic API Key", want: true},
		{name: "glued openai", arg: "9" + "sk-" + "proj-" + strings.Repeat("Qw7eR9tY", 6), pattern: "OpenAI API Key", want: true},
		{name: "glued mailgun", arg: "_key-" + strings.Repeat("a1b2c3d4", 4), pattern: "Mailgun API Key", want: true},
		{name: "glued twilio", arg: "xSK" + strings.Repeat("a1b2c3d4", 4), pattern: "Twilio API Key", want: true},
		{name: "glued card", arg: "x4111" + strings.Repeat("1", 12), pattern: "Credit Card Number", want: true},
		{name: "digit glued card", arg: "94111" + strings.Repeat("1", 12), pattern: "Credit Card Number", want: false},
		{name: "glued ssn", arg: "x123-45-6789", pattern: "Social Security Number", want: true},
		{name: "prose provider key", arg: "the desk-ant-hill-clearance-report-final", pattern: "Anthropic API Key", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"text":"` + tc.arg + `"}}}`
			verdict := ScanRequest(t.Context(), []byte(line), sc, config.ActionBlock, config.ActionBlock)
			found := false
			for _, match := range verdict.Matches {
				if match.PatternName == tc.pattern {
					found = true
				}
			}
			if found != tc.want || verdict.Error != "" {
				t.Fatalf("found=%v clean=%v err=%q matches=%+v", found, verdict.Clean, verdict.Error, verdict.Matches)
			}
		})
	}
}
