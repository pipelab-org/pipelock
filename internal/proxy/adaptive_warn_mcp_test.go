// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Exercise the production recorder, rather than a recorder that supplies a
// preselected escalation level. Repeated warnings must leave discovery usable.
func TestAdaptiveWarningsLeaveCleanMCPUsable(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.MCPInputScanning.Action = config.ActionWarn
	for i := range 25 {
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: fmt.Sprintf("Coordination %d", i), Regex: fmt.Sprintf("coordination-marker-%02d", i), Severity: config.SeverityLow})
	}
	cfg.ApplyDefaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	rec := &SessionState{}
	var input strings.Builder
	for i := range 25 {
		_, _ = fmt.Fprintf(&input, `{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"coordinate","arguments":{"text":"coordination-marker-%02d"}}}`+"\n", i+1, i)
	}
	const discovery = `{"jsonrpc":"2.0","id":100,"method":"tools/list"}`
	input.WriteString(discovery + "\n")
	var forwarded, logs bytes.Buffer
	blocked := make(chan mcp.BlockedRequest, 32)
	mcp.ForwardScannedInput(transport.NewStdioReader(strings.NewReader(input.String())), transport.NewStdioWriter(&forwarded), &logs,
		config.ActionWarn, config.ActionBlock, blocked, nil, nil,
		mcp.MCPProxyOpts{Scanner: sc, Rec: rec, AdaptiveCfg: &cfg.AdaptiveEnforcement})
	var denied []mcp.BlockedRequest
	for br := range blocked {
		denied = append(denied, br)
	}
	t.Logf("score=%.1f level=%d blocked=%d discovery_forwarded=%t", rec.ThreatScore(), rec.EscalationLevel(), len(denied), strings.Contains(forwarded.String(), discovery))
	if len(denied) != 0 || !strings.Contains(forwarded.String(), discovery) {
		t.Fatalf("warnings interrupted MCP coordination; logs:\n%s", logs.String())
	}
}
