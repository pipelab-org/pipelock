// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// Known gap: anonymous stateless callers have no cross-request taint history.
// This pins the observed compatibility behavior, not a protection guarantee.
func TestAnonymousStatelessListener_NoCrossRequestTaint_Baseline(t *testing.T) {
	for _, tc := range []struct {
		name            string
		withStore       bool
		requireIdentity bool
		withOverride    bool
	}{
		{name: "no_store"},
		{name: "store_only", withStore: true},
		{name: "store_and_identity_required", withStore: true, requireIdentity: true},
		{name: "store_and_identity_required_with_override", withStore: true, requireIdentity: true, withOverride: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				var frame struct {
					ID json.RawMessage `json:"id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&frame); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"external result"}]}}`, frame.ID)
			}))
			t.Cleanup(upstream.Close)
			cfg := config.Defaults()
			if tc.withOverride {
				cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{Scope: "action", ActionMatch: "mcp:execute_command*"}}
			}
			opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), InputCfg: newHTTPInputCfg(config.ActionBlock), TaintCfg: &cfg.Taint}
			if tc.withStore {
				opts.Store = &listenerDiagnosisStore{}
			}
			if tc.requireIdentity {
				opts.listenerStateTokenRequired = boolPtr(true)
			}
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			status, read := mustPrincipalControlRPC(t, baseURL, "", principalControlToolCall(1, "read_file", `{"path":"/workspace/security-guide.md"}`))
			_, exec := mustPrincipalControlRPC(t, baseURL, "", principalControlToolCall(2, "execute_command", `{"command":"id"}`))
			t.Logf("taint_enabled=%t store=%t first_read_status=%d first_read_error=%q scoped_exec_error=%q upstream_calls=%d", cfg.Taint.Enabled, tc.withStore, status, principalControlRPCError(t, read), principalControlRPCError(t, exec), upstreamCalls.Load())
			if tc.requireIdentity {
				if !strings.Contains(read, "authenticated principal") || !strings.Contains(exec, "authenticated principal") || upstreamCalls.Load() != 0 {
					t.Fatal("expected identity-required anonymous calls to refuse before the scoped taint allowance can help")
				}
			} else if principalControlRPCError(t, read) != "" || principalControlRPCError(t, exec) != "" || upstreamCalls.Load() != 2 {
				t.Fatal("expected anonymous compatibility calls to reach the upstream with taint enabled")
			}
		})
	}
}

// This documents the existing undeclared-origin default, not verified provenance.
func TestStdioUndeclaredOrigin_InternalGenerated_Baseline(t *testing.T) {
	opts := MCPProxyOpts{}
	observation := session.ClassifyMCPResponseObservation(mcpTaintSourceKind, opts.mcpResponseTaintExternal(), false)
	if observation.Source.Level != session.TaintInternalGenerated {
		t.Fatalf("level %s", observation.Source.Level)
	}
}
