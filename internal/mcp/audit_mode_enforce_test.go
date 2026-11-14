// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"io"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestAuditModeMCPResponseIgnoresEnforce records the response side. A core
// credential in a response is forwarded when the scanner action is warn, for
// both enforce values. Response scanning does not consult enforce.
func TestAuditModeMCPResponseIgnoresEnforce(t *testing.T) {
	response := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"` + fakeAWSKey() + `"}]}}`
	for _, enforce := range []bool{true, false} {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		cfg.Enforce = &enforce
		cfg.ResponseScanning.Action = config.ActionWarn
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		var out bytes.Buffer
		_, err := ForwardScanned(
			transport.NewStdioReader(bytes.NewReader([]byte(response+"\n"))),
			transport.NewStdioWriter(&out),
			io.Discard,
			nil,
			MCPProxyOpts{Scanner: sc, AuditMode: !enforce},
		)
		if err != nil {
			t.Fatal(err)
		}
		if out.String() != response+"\n" {
			t.Fatalf("enforce=%t warn-action response = %q", enforce, out.String())
		}
	}
}
