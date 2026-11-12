// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// decodeLimitFakeKey is a fake credential assembled at runtime.
func decodeLimitFakeKey() string { return "AK" + "IA" + strings.Repeat("V", 16) }

// decodeLimitPercentChain percent-encodes the credential's first byte n times,
// so n decoding rounds recover it.
func decodeLimitPercentChain(n int) string {
	key := decodeLimitFakeKey()
	encoded := fmt.Sprintf("%%%02X", key[0])
	for i := 1; i < n; i++ {
		encoded = strings.ReplaceAll(encoded, "%", "%25")
	}
	return "token " + encoded + key[1:] + " end"
}

// decodeLimitEntityChain stacks n entity layers over a benign byte.
func decodeLimitEntityChain(n int) string {
	return "token &" + strings.Repeat("amp;", n) + "#65; end"
}

// Past the percent-round or entity-pass limit an inbound scan can no longer
// vouch for the content. Every inbound surface delivers it with the
// partial-inspection warning and refuses nothing.
func TestInboundDecodeLimitSurfacesWarn(t *testing.T) {
	bodies := map[string]string{
		"percent": decodeLimitPercentChain(501),
		"entity":  decodeLimitEntityChain(40),
	}
	for name, body := range bodies {
		for _, surface := range []string{"mcp-response", "a2a-response", "generic-sse", "a2a-sse"} {
			t.Run(name+"/"+surface, func(t *testing.T) {
				runInboundPartialSurface(t, surface, body)
			})
		}
	}
}

// The MCP tool-result verdict carries the warning as informational DLP
// evidence, and a result inside the limits carries none.
func TestInboundDecodeLimitMCPVerdict(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.ResponseScanning.Action = config.ActionBlock
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	toolResult := func(text string) []byte {
		line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []map[string]string{{"type": "text", "text": text}}}})
		if err != nil {
			t.Fatal(err)
		}
		return line
	}
	for name, body := range map[string]string{
		"percent": decodeLimitPercentChain(501),
		"entity":  decodeLimitEntityChain(40),
	} {
		t.Run(name, func(t *testing.T) {
			v := ScanResponse(toolResult(body), sc)
			if v.Error != "" || v.Clean || v.Action != config.ActionWarn || len(v.Matches) != 0 {
				t.Fatalf("decode-limit tool result is not a plain warning: clean=%v action=%q err=%q matches=%d", v.Clean, v.Action, v.Error, len(v.Matches))
			}
			if !scanner.OnlyInformational(v.DLPMatches) || !hasNamedDLP(v.DLPMatches, scanner.PartialEncodedContentPattern) {
				t.Fatalf("verdict lost the partial-inspection warning: %v", v.DLPMatches)
			}
		})
	}
	for name, body := range map[string]string{
		"percent inside limit": decodeLimitPercentChain(3),
		"entity inside limit":  decodeLimitEntityChain(3),
		"plain":                "ordinary tool output",
	} {
		t.Run(name, func(t *testing.T) {
			v := ScanResponse(toolResult(body), sc)
			if hasNamedDLP(v.DLPMatches, scanner.PartialEncodedContentPattern) {
				t.Fatalf("warning fired inside the limits: %v", v.DLPMatches)
			}
		})
	}
}

// Redirect handler output is scanned with the inbound marker on the outbound
// text entry point. A decode-limit stop there stays a warning: the merged
// verdict must remain clean so the redirect is delivered.
func TestInboundDecodeLimitRedirectOutputNotBlocked(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	for name, body := range map[string]string{
		"percent": decodeLimitPercentChain(501),
		"entity":  decodeLimitEntityChain(40),
	} {
		t.Run(name, func(t *testing.T) {
			dlp := sc.ScanTextForDLP(scanner.WithInboundDirection(t.Context()), body)
			if !hasNamedDLP(dlp.Matches, scanner.PartialEncodedContentPattern) {
				t.Fatalf("redirect output scan lost the warning: %v", dlp.Matches)
			}
			merged := mergeRedirectResponseDLP(jsonrpc.ScanVerdict{Clean: true}, dlp)
			if !merged.Clean || merged.Error != "" || !scanner.OnlyInformational(merged.DLPMatches) {
				t.Fatalf("decode-limit redirect output refused: clean=%v err=%q", merged.Clean, merged.Error)
			}
		})
	}
}
