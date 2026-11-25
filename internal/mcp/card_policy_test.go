// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardBarePolicyRequestTransports(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	numeric := cardtest.Issuer("453912341234123", 16)
	for _, surface := range []string{"stdio", "http bridge JSON", "http bridge SSE", "http listener JSON", "http listener SSE", "websocket"} {
		for _, action := range []string{config.ActionBlock, config.ActionWarn} {
			for _, tc := range []struct {
				name, args string
				block      bool
			}{
				{"bare", `{"value":"` + pan + `"}`, action == config.ActionBlock},
				{"derived number", `{"value":` + pan + `e0}`, true},
				{"key", `{"card":"` + pan + `"}`, true},
				{"long key context", `{"card":"` + strings.Repeat("x", 150) + ` ` + pan + `"}`, true},
				{"key numeric array", `{"card":["` + strings.Repeat("x", 150) + `",` + numeric[:4] + `,` + numeric[4:8] + `,` + numeric[8:12] + `,` + numeric[12:] + `]}`, true},
				{"long key array", `{"card":["other","` + strings.Repeat("x", 150) + ` ` + pan + `"]}`, true},
				{"key tab", `{"card":"` + pan[:4] + `\t` + pan[4:] + `"}`, true},
				{"decimal", `{"value":"F27=` + pan[:4] + `.` + pan[4:] + `"}`, false},
				{"corroborated", `{"value":"visa ` + pan[:4] + `.` + pan[4:] + `"}`, true},
			} {
				t.Run(surface+"/"+action+"/"+tc.name, func(t *testing.T) {
					cfg := config.Defaults()
					cfg.Internal = nil
					cfg.DLP.ScanEnv = false
					cfg.DLP.CardBareAction = action
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					opts := testOpts(sc)
					opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock}
					request := `{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":` + tc.args + `,"name":"metrics"}}`
					want := request
					if tc.block {
						want = ""
					}
					output := runCardRequestTransport(t, surface, request, want, opts)
					if tc.block && !strings.Contains(output, "-32001") {
						t.Fatalf("missing block: %s", output)
					}
				})
			}
		}
	}
}

func TestCardBarePolicyResponseAndA2A(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, action := range []string{config.ActionBlock, config.ActionWarn} {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.CardBareAction = action
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		a2a := enabledA2ACfg()
		a2a.Action = config.ActionBlock
		for _, tc := range []struct {
			text  string
			block bool
		}{
			{pan, action == config.ActionBlock},
			{"visa " + pan[:4] + "." + pan[4:], true},
			{"F27=" + pan[:4] + "." + pan[4:], false},
		} {
			body := `{"text":"` + tc.text + `"}`
			response := []byte(`{"jsonrpc":"2.0","id":1,"result":` + body + `}`)
			result := ScanResponseOpts(response, sc, ResponseScanOptions{ActionOverride: config.ActionBlock})
			if got := !result.Clean && result.Action == config.ActionBlock; got != tc.block {
				t.Fatalf("MCP %s %q: %+v", action, tc.text, result)
			}
			ar := ScanA2ARequestBody(t.Context(), []byte(body), sc, a2a)
			if got := !ar.Clean && ar.Action == config.ActionBlock; got != tc.block {
				t.Fatalf("A2A %s %q: %+v", action, tc.text, ar)
			}
		}
	}
}
