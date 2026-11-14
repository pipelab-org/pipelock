// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

// auditChainSessionCap mirrors the chain matcher's tracked-session cap. The
// test fails loudly if the cap moves, because the fill below would no longer
// reach it.
const auditChainSessionCap = 4096

// TestMCPAuditModeStdioChainCapacityStaysRefused fills the chain matcher with
// other sessions, then sends one stdio tool call. The matcher cannot track the
// stdio session, which is a resource limit and not a configured pattern, so
// the call is refused whether or not enforcement is on.
func TestMCPAuditModeStdioChainCapacityStaysRefused(t *testing.T) {
	for _, audit := range []bool{false, true} {
		t.Run(auditLabel(audit), func(t *testing.T) {
			matcher := chains.New(&config.ToolChainDetection{
				Enabled: true, Action: config.ActionWarn, WindowSize: 4, WindowSeconds: 300,
			})
			for i := range auditChainSessionCap {
				matcher.Record(fmt.Sprintf("other-session-%d", i), "read_file")
			}
			if v := matcher.Record("probe-session", "read_file"); v.PatternMatch || v.Action != config.ActionBlock {
				t.Fatalf("matcher is not at capacity: %+v", v)
			}
			opts := MCPProxyOpts{
				Scanner:      auditTestScanner(t, nil),
				AuditMode:    audit,
				ChainMatcher: matcher,
				InputCfg:     &InputScanConfig{Enabled: true, Action: config.ActionWarn, OnParseError: config.ActionBlock},
			}
			call := makeRequest(1, methodToolsCall, map[string]any{"name": "read_file", "arguments": map[string]any{}})
			var server, logs bytes.Buffer
			blocked := make(chan BlockedRequest, 2)
			ForwardScannedInput(
				transport.NewStdioReader(strings.NewReader(call+"\n")),
				transport.NewStdioWriter(&server),
				&logs, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts,
			)
			var blockedN int
			for range blocked {
				blockedN++
			}
			if blockedN != 1 || server.Len() != 0 {
				t.Fatalf("stdio call past chain capacity: blocked=%d forwarded=%q log=%s", blockedN, server.String(), logs.String())
			}
		})
	}
}

// TestMCPAuditModeListenerBaselineFailureStaysRefused runs a listener whose
// baseline store fails every check. A failed check is not a deviation, so the
// tool call is refused in both modes and never reaches the upstream.
func TestMCPAuditModeListenerBaselineFailureStaysRefused(t *testing.T) {
	for _, audit := range []bool{false, true} {
		t.Run(auditLabel(audit), func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
			}))
			t.Cleanup(upstream.Close)
			opts := MCPProxyOpts{
				Scanner:                auditTestScanner(t, nil),
				AuditMode:              audit,
				Baseline:               failingMetricsBaselineChecker{},
				BaselineRec:            &baselineTestRecorder{},
				AddressProtectionAgent: "id-k",
			}
			base, logs := startListenerProxyWithOpts(t, upstream.URL, opts)
			body := postListenerTool(t, base, auditTool("audit_probe", map[string]string{"text": "hello"}))
			if hits.Load() != 0 || !strings.Contains(body, "error") {
				t.Fatalf("listener released a call with a failing baseline store: hits=%d body=%s", hits.Load(), body)
			}
			if !strings.Contains(logs.String(), "baseline check failed") {
				t.Fatalf("refusal did not come from the baseline check: %s", logs.String())
			}
		})
	}
}
