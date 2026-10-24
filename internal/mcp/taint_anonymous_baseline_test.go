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

// Anonymous stateless listener callers have no cross-request taint history;
// that gap is documented in docs/configuration.md and reported by doctor and
// explain. These cases cover the controls that do close it: requiring caller
// identity refuses anonymous calls before any taint allowance applies, and a
// verified caller making the same read-then-exec calls under the default taint
// policy is refused on the exec.
func TestHTTPListener_TaintControlsForStatelessCallers(t *testing.T) {
	for _, tc := range []struct {
		name            string
		withStore       bool
		requireIdentity bool
		withOverride    bool
		verified        bool
	}{
		{name: "store_and_identity_required", withStore: true, requireIdentity: true},
		{name: "store_and_identity_required_with_override", withStore: true, requireIdentity: true, withOverride: true},
		{name: "verified_principal_control", withStore: true, verified: true},
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
			bearer := ""
			if tc.verified {
				bearer = principalStateTestBearer
				opts.ListenerBearerToken = bearer
				opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
					return ListenerPrincipal{Provider: "test", Subject: "alice"}, nil
				}
			}
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			status, read := mustPrincipalControlRPC(t, baseURL, bearer, principalControlToolCall(1, "read_file", `{"path":"/workspace/security-guide.md"}`))
			_, exec := mustPrincipalControlRPC(t, baseURL, bearer, principalControlToolCall(2, "execute_command", `{"command":"id"}`))
			t.Logf("taint_enabled=%t store=%t first_read_status=%d first_read_error=%q scoped_exec_error=%q upstream_calls=%d", cfg.Taint.Enabled, tc.withStore, status, principalControlRPCError(t, read), principalControlRPCError(t, exec), upstreamCalls.Load())
			switch {
			case tc.verified:
				if principalControlRPCError(t, read) != "" || !strings.Contains(principalControlRPCError(t, exec), "mutating_exec_after_untrusted_external_exposure") || upstreamCalls.Load() != 1 {
					t.Fatal("expected a verified caller's exec after the external read to be refused by cross-request taint")
				}
			case tc.requireIdentity:
				if !strings.Contains(read, "authenticated principal") || !strings.Contains(exec, "authenticated principal") || upstreamCalls.Load() != 0 {
					t.Fatal("expected identity-required anonymous calls to refuse before the scoped taint allowance can help")
				}
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
