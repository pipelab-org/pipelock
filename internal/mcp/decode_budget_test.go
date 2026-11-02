// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func decodeBudgetBody(name string) (string, string) {
	switch name {
	case "json":
		return `{"message":"` + strings.Repeat("!", 5_240_000-20) + `\u0061"}`, "application/json"
	case "hex":
		return strings.Repeat("21", 3*1024*1024/2), "text/plain"
	case "base64":
		n := 9 * 1024 * 1024 / 4 * 3
		plain := bytes.Repeat([]byte{0xff}, n)
		return base64.StdEncoding.EncodeToString(plain), "text/plain"
	default:
		panic("unknown decode workload")
	}
}

func TestDecodeBudgetLargeStdioInput(t *testing.T) {
	for _, name := range []string{"json", "hex", "base64"} {
		t.Run(name, func(t *testing.T) {
			body, _ := decodeBudgetBody(name)
			msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "upload", "arguments": map[string]string{"text": body}}})
			if err != nil {
				t.Fatal(err)
			}
			msg = append(msg, '\n')
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			var server, logs bytes.Buffer
			blocked := make(chan BlockedRequest, 1)
			ForwardScannedInput(transport.NewStdioReader(bytes.NewReader(msg)), transport.NewStdioWriter(&server), &logs, config.ActionBlock, config.ActionBlock, blocked, nil, nil, buildTestOpts(sc))
			if request, ok := <-blocked; ok {
				t.Fatalf("%d-byte input refused: %+v", len(body), request)
			}
			if !bytes.Equal(server.Bytes(), msg) {
				t.Fatalf("stdio forwarded %d bytes, want %d", server.Len(), len(msg))
			}
			t.Logf("delivered %d-byte body (%d-byte message)", len(body), len(msg))
		})
	}
}

func TestDecodeBudgetInboundURLPolicy(t *testing.T) {
	nested := `\u0068ello`
	for range 80 {
		nested = strings.ReplaceAll(nested, `\`, `\u005c`)
	}
	uri := "https://api.vendor.example/" + strings.Repeat("!", 128*1024) + nested
	for _, largeLimit := range []bool{false, true} {
		name := "fallback floor"
		if largeLimit {
			name = "direct floor"
		}
		t.Run(name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.APIAllowlist = nil
			cfg.DLP.ScanEnv = false
			if largeLimit {
				cfg.FetchProxy.Monitoring.MaxURLLength = len(uri) + 1
			}
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			a2a := enabledA2ACfg()
			a2a.Action = config.ActionWarn
			body, err := json.Marshal(map[string]any{"file": map[string]string{"uri": uri}})
			if err != nil {
				t.Fatal(err)
			}
			out := ScanA2ARequestBody(t.Context(), body, sc, a2a)
			if out.Action != config.ActionBlock {
				t.Fatal("outbound URL work limit did not block")
			}
			found := false
			for _, finding := range out.URLFindings {
				found = found || scanner.IsURLInspectionLimitResult(finding)
			}
			if !found {
				t.Fatal("outbound refusal did not include the URL work limit")
			}
			in := ScanA2AResponseBody(t.Context(), body, sc, a2a)
			if in.Action == config.ActionBlock {
				t.Fatal("inbound URL refused at a work limit")
			}
			for _, finding := range in.URLFindings {
				if scanner.IsURLInspectionLimitResult(finding) {
					t.Fatal("inbound URL acquired a new work limit")
				}
			}
			// The prior URL depth and credential floors still hold for responses.
			// docs/bypass-resistance.md pins 500 rounds; this needs 501.
			percent := "%68"
			for range 500 {
				percent = strings.ReplaceAll(percent, "%", "%25")
			}
			for _, protectedURI := range []string{"https://api.vendor.example/" + percent + "ello", "https://api.vendor.example/" + "AK" + "IA" + "Q9W8E7R6T5Y4U3I2"} {
				protected, marshalErr := json.Marshal(map[string]any{"file": map[string]string{"uri": protectedURI}})
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				if result := ScanA2AResponseBody(t.Context(), protected, sc, a2a); result.Action != config.ActionBlock {
					t.Fatal("inbound URL lost an existing depth or credential floor")
				}
			}
		})
	}
}
