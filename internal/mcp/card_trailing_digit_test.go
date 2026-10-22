// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func trailingDigitMCPScanner(t *testing.T) *scanner.Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.ResponseScanning.Action = config.ActionBlock
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	return s
}

func TestTrailingDigitCardMCP(t *testing.T) {
	s := trailingDigitMCPScanner(t)
	for _, tt := range cardtest.TrailingDigitCases() {
		t.Run(tt.Name, func(t *testing.T) {
			text, err := json.Marshal(tt.Text)
			if err != nil {
				t.Fatal(err)
			}
			request := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"report","arguments":{"note":` + string(text) + `}}}`)
			if v := ScanRequest(t.Context(), request, s, config.ActionBlock, config.ActionBlock); v.Clean != tt.Clean || v.Error != "" {
				t.Fatalf("MCP request clean=%v error=%q want=%v", v.Clean, v.Error, tt.Clean)
			}
			response := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + string(text) + `}]}}`)
			if v := ScanResponse(response, s); v.Clean != tt.Clean || v.Error != "" {
				t.Fatalf("MCP response clean=%v error=%q want=%v", v.Clean, v.Error, tt.Clean)
			}
			stream := "data: " + string(response) + "\n\n"
			var forwarded bytes.Buffer
			err = ScanGenericSSEStream(t.Context(), strings.NewReader(stream), &forwarded, nil, s, enabledSSECfg())
			if (err == nil) != tt.Clean {
				t.Fatalf("SSE error=%v want clean=%v", err, tt.Clean)
			}
			if !tt.Clean {
				if !errors.Is(err, ErrSSEStreamFinding) {
					t.Fatalf("SSE error=%v want stream finding", err)
				}
				if strings.Contains(forwarded.String(), tt.Card) {
					t.Fatal("SSE forwarded blocked card")
				}
			}
		})
	}
}

// Response leaves are joined with a separator the card rule can consume, so a
// whole-leaf card followed by a digit-led leaf used to scan clean.
func TestTrailingDigitCardMCPWholeLeafNeighbour(t *testing.T) {
	s := trailingDigitMCPScanner(t)
	card := cardtest.Number()
	invalid := card[:15] + "2"
	for _, tt := range []struct {
		name, first, second string
		clean               bool
	}{
		{"quantity leaf", card, "2 apples", false},
		{"expiry leaf", card, "12/27", false},
		{"invalid checksum leaf", invalid, "2 apples", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			blocks := `[{"type":"text","text":"` + tt.first + `"},{"type":"text","text":"` + tt.second + `"}]`
			for _, response := range []string{
				`{"jsonrpc":"2.0","id":1,"result":{"content":` + blocks + `}}`,
				`{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"card":"` + tt.first + `","note":"` + tt.second + `"}}}`,
			} {
				if v := ScanResponse([]byte(response), s); v.Clean != tt.clean || v.Error != "" {
					t.Fatalf("clean=%v error=%q want=%v for %s", v.Clean, v.Error, tt.clean, response)
				}
			}
		})
	}
}
