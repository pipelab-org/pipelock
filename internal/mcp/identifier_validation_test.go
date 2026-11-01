// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestMCPIdentifierValidation(t *testing.T) {
	for _, validator := range []string{"", config.ValidatorDEA} {
		t.Run("validator="+validator, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.Patterns = []config.DLPPattern{{Name: "dea", Regex: `\b[ABFMPRSX][A-Z9]\d{7}\b`, Severity: config.SeverityCritical, Validator: validator}}
			s := scanner.MustNew(cfg)
			t.Cleanup(s.Close)
			valid, invalid := "FA"+"9876547", "fa"+"9876543"
			for _, tt := range []struct {
				name, text string
				valid      bool
			}{
				{"valid lowercase", strings.ToLower(valid), true},
				{"valid encoded", base64.StdEncoding.EncodeToString([]byte(valid)), true},
				{"invalid revision", "Revision " + invalid + " in release.notes", false},
				{"invalid labeled", "DEA: " + invalid, false},
				{"decoy and valid", invalid + "; " + valid, true},
			} {
				t.Run(tt.name, func(t *testing.T) {
					for _, result := range []string{
						fmt.Sprintf(`{"content":[{"type":"text","text":%q}]}`, tt.text),
						fmt.Sprintf(`{"structuredContent":{"note":%q}}`, tt.text),
					} {
						line := []byte(`{"jsonrpc":"2.0","id":1,"result":` + result + `}`)
						got := ScanResponseOpts(line, s, ResponseScanOptions{ActionOverride: config.ActionBlock})
						want := tt.valid || validator == ""
						if got.Error != "" || !got.Clean != want {
							t.Fatalf("response clean=%v error=%s, want finding %v", got.Clean, got.Error, want)
						}
						if want && (got.Action != config.ActionBlock || len(got.DLPMatches) == 0) {
							t.Fatalf("missing DLP block: action=%s matches=%d", got.Action, len(got.DLPMatches))
						}
					}
				})
			}
		})
	}
}

func TestMCPIdentifierValidationLabeled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "labeled dea", Regex: `\bdea[\s:#=]{1,4}[ABFMPRSX][A-Z9]\d{7}\b`, Severity: config.SeverityCritical, Validator: config.ValidatorDEA}}
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	for _, tt := range []struct {
		name, text string
		want       bool
	}{
		{"valid", "DEA: AB" + "1234563", true},
		{"invalid", "DEA: AB" + "1234567", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			line := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":%q}]}}`, tt.text))
			got := ScanResponseOpts(line, s, ResponseScanOptions{ActionOverride: config.ActionBlock})
			if got.Error != "" || !got.Clean != tt.want {
				t.Fatalf("clean=%v error=%s, want finding=%v", got.Clean, got.Error, tt.want)
			}
			if tt.want && (got.Action != config.ActionBlock || len(got.DLPMatches) == 0 || got.DLPMatches[0].PatternName != "labeled dea") {
				t.Fatal("expected labeled DEA rule to block")
			}
		})
	}
}
