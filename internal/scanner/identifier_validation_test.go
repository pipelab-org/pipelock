// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The regexes are the existing healthcare bundle contracts. Validators are
// explicit opt-ins; an unchanged shape-only rule must retain its behavior.
func TestStructuredIdentifierValidation(t *testing.T) {
	for _, rule := range []struct {
		name, regex, validator, valid, invalid string
	}{
		{"dea", `\b[ABFMPRSX][A-Z9]\d{7}\b`, config.ValidatorDEA, "FA" + "9876547", "fa" + "9876543"},
		{"dea labeled", `\bdea[\s:#=]{1,4}[ABFMPRSX][A-Z9]\d{7}\b`, config.ValidatorDEA, "DEA: FA" + "9876547", "DEA: fa" + "9876543"},
		{"npi", `\b(?:npi|national[\s_-]?provider[\s_-]?(?:id|identifier)?)[\s:#=]{1,4}[12]\d{9}\b`, config.ValidatorNPI, "NPI: 1234567893", "NPI: 1234567890"},
		{"aba", `\b(?:routing|aba|rtn)[\s:#=]{1,4}\d{9}\b`, config.ValidatorABA, "routing: 021000021", "routing: 021000022"},
	} {
		t.Run(rule.name, func(t *testing.T) {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("validator=%v", enabled), func(t *testing.T) {
					cfg := testConfig()
					cfg.FetchProxy.Monitoring.MaxURLLength = 1 << 20
					cfg.FetchProxy.Monitoring.EntropyThreshold = 10
					p := config.DLPPattern{Name: rule.name, Regex: rule.regex, Severity: config.SeverityCritical}
					if enabled {
						p.Validator = rule.validator
					}
					cfg.DLP.Patterns = []config.DLPPattern{p}
					if err := cfg.Validate(); err != nil {
						t.Fatal(err)
					}
					s, err := New(cfg)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(s.Close)
					for _, input := range []struct {
						name, text string
						valid      bool
					}{
						{"valid", rule.valid, true},
						{"invalid", rule.invalid, false},
						{"decoys before valid", strings.Repeat(rule.invalid+"; ", 12) + rule.valid, true},
						{"valid before decoys", rule.valid + "; " + rule.invalid, true},
					} {
						for _, transform := range []struct {
							name  string
							apply func(string) string
						}{
							{"plain", func(s string) string { return s }},
							{"lowercase", strings.ToLower},
							{"hex", func(s string) string { return hex.EncodeToString([]byte(s)) }},
							{"base64", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }},
							{"nested", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte(s)))) }},
						} {
							t.Run(input.name+"/"+transform.name, func(t *testing.T) {
								text := transform.apply(input.text)
								want := input.valid || !enabled
								for _, scan := range []struct {
									name string
									fn   func(context.Context, string) TextDLPResult
								}{
									{"outbound", s.ScanTextForDLP},
									{"inbound", s.ScanTextForDLPInbound},
								} {
									got := scan.fn(context.Background(), text)
									if !got.Clean != want {
										t.Fatalf("%s finding=%v, want %v", scan.name, !got.Clean, want)
									}
								}
								got := s.Scan(context.Background(), "https://api.vendor.example/"+text)
								if !got.Allowed != want {
									t.Fatalf("URL allowed=%v reason=%s, want finding %v", got.Allowed, got.Reason, want)
								}
								if want && got.Scanner != "dlp" {
									t.Fatalf("URL rejected by %s, want dlp", got.Scanner)
								}
							})
						}
					}
				})
			}
		})
	}
}
