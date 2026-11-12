// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestScanRequestBodyGluedBoundaryAndByteList(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	anthropic := "sk-" + "ant-" + "api03-" + strings.Repeat("Ab3dE6gH", 11) + "-xY" + "AA"
	cases := []struct {
		name, body, pattern string
		want                bool
	}{
		{name: "glued anthropic", body: `{"text":"x` + anthropic + `"}`, pattern: "Anthropic API Key", want: true},
		{name: "glued openai", body: `{"text":"9` + "sk-" + "proj-" + strings.Repeat("Qw7eR9tY", 6) + `"}`, pattern: "OpenAI API Key", want: true},
		{name: "glued mailgun", body: `{"text":"_key-` + strings.Repeat("a1b2c3d4", 4) + `"}`, pattern: "Mailgun API Key", want: true},
		{name: "glued twilio", body: `{"text":"xSK` + strings.Repeat("a1b2c3d4", 4) + `"}`, pattern: "Twilio API Key", want: true},
		{name: "glued card", body: `{"text":"x4111` + strings.Repeat("1", 12) + `"}`, pattern: "Credit Card Number", want: true},
		{name: "digit glued card", body: `{"text":"94111` + strings.Repeat("1", 12) + `"}`, pattern: "Credit Card Number", want: false},
		{name: "glued ssn", body: `{"text":"x123-45-6789"}`, pattern: "Social Security Number", want: true},
		{name: "prose provider key", body: `{"text":"the desk-ant-hill-clearance-report-final"}`, pattern: "Anthropic API Key", want: false},
		{name: "letter byte list", body: `{"text":"` + proxyByteList("AKIA"+"0123456789ABCDEF", "x") + `"}`, pattern: "AWS Access ID", want: true},
		{name: "dot byte list", body: `{"text":"` + proxyByteList("AKIA"+"0123456789ABCDEF", ".") + `"}`, pattern: "AWS Access ID", want: true},
		{name: "version string", body: `{"text":"version 1.2.3 shipped 2026-11-11 at 203.0.113.10 id_123_456"}`, pattern: "AWS Access ID", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, result := scanRequestBody(context.Background(), BodyScanRequest{
				Body:        strings.NewReader(tc.body),
				ContentType: contentTypeJSON,
				MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
				Scanner:     sc,
				Action:      cfg.RequestBodyScanning.Action,
			})
			found := hasDLPMatchName(result.DLPMatches, tc.pattern)
			if found != tc.want {
				t.Fatalf("found=%v clean=%v matches=%v", found, result.Clean, dlpMatchNames(result.DLPMatches))
			}
		})
	}
}

func proxyByteList(secret, glue string) string {
	parts := make([]string, len(secret))
	for i := 0; i < len(secret); i++ {
		parts[i] = strconv.Itoa(int(secret[i]))
	}
	return strings.Join(parts, glue)
}
