// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestIdentifierChecksums(t *testing.T) {
	for _, tt := range []struct {
		name, text string
		validate   func(string) bool
		want       bool
	}{
		{"DEA valid", "AB" + "1234563", validateDEA, true},
		{"DEA lowercase", "ab" + "1234563", validateDEA, true},
		{"DEA second character nine", "M9" + "1234563", validateDEA, true},
		{"DEA labeled", "DEA: AB" + "1234563", validateDEA, true},
		{"DEA invalid decoy in one match", "DEA: AB" + "1234567; AB" + "1234563", validateDEA, true},
		{"DEA invalid labeled", "DEA: AB" + "1234567", validateDEA, false},
		{"DEA invalid checksum", "AB" + "1234567", validateDEA, false},
		{"DEA empty", "", validateDEA, false},
		{"DEA short", "AB123456", validateDEA, false},
		{"DEA long", "AB12345630", validateDEA, false},
		{"DEA nonletter first", "1B1234563", validateDEA, false},
		{"DEA nonletter second", "A11234563", validateDEA, false},
		{"DEA nondigit", "AB12345x3", validateDEA, false},
		{"DEA unicode", "Aſ1234563", validateDEA, false},
		{"NPI CMS example", "1234567893", validateNPI, true},
		{"NPI label", "NPI: 1234567893", validateNPI, true},
		{"NPI invalid checksum", "1234567890", validateNPI, false},
		{"NPI empty", "", validateNPI, false},
		{"NPI short", "123456789", validateNPI, false},
		{"NPI long", "12345678930", validateNPI, false},
		{"NPI unicode digits", "１２３４５６７８９３", validateNPI, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.validate(tt.text); got != tt.want {
				t.Fatalf("checksum result=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestDEAPrefixesAndWhitespace(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "dea", Regex: `\b[ABFMPRSX][A-Z9]\d{7}\b`, Severity: config.SeverityCritical, Validator: config.ValidatorDEA}}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	for _, prefix := range "ABFMPRSX" {
		for check := range 10 {
			t.Run(fmt.Sprintf("%c/check=%d", prefix, check), func(t *testing.T) {
				value := fmt.Sprintf("%c9123456%d", prefix, check)
				for _, text := range []string{value, strings.ToLower(value), "DEA: " + value, value[:4] + " \n" + value[4:]} {
					for _, scan := range []func(context.Context, string) TextDLPResult{s.ScanTextForDLP, s.ScanTextForDLPInbound} {
						got := scan(context.Background(), text)
						if !got.Clean != (check == 3) {
							t.Fatalf("finding=%v, want %v", !got.Clean, check == 3)
						}
					}
				}
			})
		}
	}
}
