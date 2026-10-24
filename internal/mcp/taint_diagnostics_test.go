// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestMCPTaintDiagnostics_ActualRecorderAndReload(t *testing.T) {
	cfg := config.Defaults()
	for _, binding := range []string{"stdio_subprocess", "stdio_http", "stdio_ws", "listener_principal", "listener_legacy", "listener_token", "listener_stateless"} {
		t.Run(binding, func(t *testing.T) {
			for _, rec := range []session.Recorder{nil, &mockRecorder{}, &taintRecorder{}} {
				live := cfg.Taint
				opts := MCPProxyOpts{TaintCfgFn: func() *config.TaintConfig { return &live }, Metrics: metrics.New()}
				for phase, enabled := range []bool{true, true, false, true} {
					live.Enabled = enabled
					live.Policy = config.ModeBalanced
					if phase == 1 {
						live.Policy = config.ModePermissive
					}
					var out bytes.Buffer
					reportMCPTaint(&out, opts, rec, binding)
					want := "inactive"
					_, records := rec.(session.RiskState)
					if !enabled {
						want = "disabled"
					} else if records && binding != "listener_stateless" {
						want = "active"
					}
					for _, fragment := range []string{"binding=" + binding, fmt.Sprintf("recorder_risk_state=%t cross_request_recording=%s", records, want), "in-memory scope", "taint_policy=" + live.Policy, "origin=undeclared", "response_action=unspecified", "terminal_approval=false"} {
						if !strings.Contains(out.String(), fragment) {
							t.Fatalf("missing %q: %s", fragment, out.String())
						}
					}
					if binding == "listener_stateless" && !strings.Contains(out.String(), "cross-request taint protection is NOT active; use verified caller identity") {
						t.Fatal("anonymous recorder confused with persistent protection")
					}
					w := httptest.NewRecorder()
					opts.Metrics.PrometheusHandler().ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
					if !strings.Contains(w.Body.String(), fmt.Sprintf(`binding=%q,status=%q`, binding, want)) {
						t.Fatal("runtime reporting did not reach metrics")
					}
				}
			}
		})
	}
	reportMCPTaint(nil, MCPProxyOpts{}, nil, "stdio_subprocess")
}

func TestMCPTaintDiagnostics_SourceAndEffectiveAction(t *testing.T) {
	for _, tc := range []struct {
		name, action, origin, effective string
		external, trusted, terminal     bool
	}{
		{name: "undeclared", action: config.ActionBlock, origin: "origin=undeclared", effective: config.ActionBlock},
		{name: "external", external: true, action: config.ActionWarn, origin: "origin=external_untrusted", effective: config.ActionWarn},
		{name: "trusted", external: true, trusted: true, action: config.ActionAsk, origin: "origin=operator-trusted", effective: config.ActionBlock},
		{name: "terminal", external: true, terminal: true, action: config.ActionAsk, origin: "origin=external_untrusted", effective: config.ActionAsk},
	} {
		t.Run(tc.name, func(t *testing.T) {
			approver := hitl.New(1, hitl.WithTerminal(tc.terminal))
			defer approver.Close()
			opts := MCPProxyOpts{
				Approver: approver, TaintExternalSource: tc.external,
				TaintTrustedSourceFn:     func() bool { return tc.trusted },
				ResponseActionOverrideFn: func() string { return tc.action },
			}
			var out bytes.Buffer
			reportMCPTaint(&out, opts, nil, "stdio_http")
			for _, want := range []string{tc.origin, "response_action=" + tc.action, "effective_response_action=" + tc.effective, fmt.Sprintf("terminal_approval=%t", tc.terminal)} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %q: %s", want, out.String())
				}
			}
		})
	}
}

func TestMCPTaintDiagnostics_StdioEntrypoints(t *testing.T) {
	for _, surface := range []string{"stdio_subprocess", "stdio_http", "stdio_ws"} {
		t.Run(surface, func(t *testing.T) {
			cfg := config.Defaults()
			opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Store: &listenerDiagnosisStore{}}
			var out, log bytes.Buffer
			var err error
			switch surface {
			case "stdio_subprocess":
				err = RunProxy(context.Background(), strings.NewReader(""), &out, &log, []string{"echo", cleanResponse}, opts)
			case "stdio_http":
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusMethodNotAllowed) }))
				defer upstream.Close()
				err = RunHTTPProxy(context.Background(), strings.NewReader(""), &out, &log, upstream.URL, nil, opts)
			case "stdio_ws":
				upstream, _ := wsDrainServer(t)
				defer upstream.Close()
				err = RunWSProxy(context.Background(), strings.NewReader(""), &out, &log, wsURL(upstream), opts)
			}
			if err != nil {
				t.Fatal(err)
			}
			origin := "origin=external_untrusted"
			if surface == "stdio_subprocess" {
				origin = "origin=undeclared"
			}
			for _, want := range []string{"binding=" + surface, "recorder_risk_state=true cross_request_recording=active", "terminal_approval=false", origin, "response_action=" + opts.Scanner.ResponseAction()} {
				if !strings.Contains(log.String(), want) {
					t.Errorf("entrypoint omitted %q: %s", want, log.String())
				}
			}
		})
	}
}

func TestMCPTaintDiagnostics_ListenerBindings(t *testing.T) {
	for _, tc := range []struct {
		name, binding, status    string
		store, principal, legacy bool
	}{
		{"anonymous_no_store", "listener_stateless", "inactive", false, false, false},
		{"anonymous_with_store", "listener_stateless", "inactive", true, false, false},
		{"principal_with_store", "listener_principal", "active", true, true, false},
		{"principal_no_store", "listener_principal", "inactive", false, true, false},
		{"legacy_with_store", "listener_legacy", "active", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log *bytes.Buffer
			// Read the log only after listener shutdown, so the buffer has no writer.
			t.Run("request", func(t *testing.T) {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, cleanResponse)
				}))
				t.Cleanup(upstream.Close)
				cfg := config.Defaults()
				opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint}
				if tc.store {
					opts.Store = &listenerDiagnosisStore{}
				}
				if tc.principal {
					opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
						return ListenerPrincipal{Provider: "test", Subject: "verified-subject"}, nil
					}
				}
				var base string
				base, log = startListenerProxyWithOpts(t, upstream.URL, opts)
				if tc.legacy {
					req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Accept", "application/json, text/event-stream")
					req.Header.Set("Mcp-Protocol-Version", "2025-03-26")
					req.Header.Set("Mcp-Method", "tools/call")
					req.Header.Set("Mcp-Name", "read_file")
					req.Header.Set("Mcp-Session-Id", "legacy-session")
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					body, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("legacy status %d: %s", resp.StatusCode, body)
					}
				} else {
					status, _ := mustPrincipalControlRPC(t, base, "", principalControlToolCall(1, "read_file", `{}`))
					if status != http.StatusOK {
						t.Fatalf("status %d", status)
					}
				}
			})
			for _, want := range []string{"binding=" + tc.binding, "cross_request_recording=" + tc.status} {
				if log == nil || !strings.Contains(log.String(), want) {
					t.Fatalf("missing %q: %v", want, log)
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

func TestMCPTaintDiagnostics_RefusalNamesConsultedRecovery(t *testing.T) {
	for _, surface := range []string{"stdio", "http"} {
		t.Run(surface, func(t *testing.T) {
			cfg := config.Defaults()
			rec := &taintRecorder{}
			rec.ObserveRisk(session.ClassifyMCPResponseObservation(mcpTaintSourceKind, true, true))
			opts := MCPProxyOpts{Scanner: testScannerWithAction(t, config.ActionWarn), Rec: rec, TaintCfg: &cfg.Taint}
			msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"id"}}}`)
			var blocked *BlockedRequest
			var log bytes.Buffer
			if surface == "http" {
				blocked = scanHTTPInput(msg, &log, "session", "session", opts)
			} else {
				ch := make(chan BlockedRequest, 1)
				ForwardScannedInput(transport.NewStdioReader(bytes.NewReader(append(msg, '\n'))), transport.NewStdioWriter(io.Discard), &log, config.ActionBlock, config.ActionBlock, ch, nil, nil, opts)
				select {
				case b := <-ch:
					blocked = &b
				default:
				}
			}
			if blocked == nil {
				t.Fatal("hostile exec was not refused")
			}
			if blocked.ErrorMessage != "pipelock: sensitive_action_after_hostile_external_exposure" || blocked.ErrorCode != -32002 {
				t.Errorf("client error changed: %+v", blocked)
			}
			for _, want := range []string{"Every MCP session", "runtime trust grants are rejected for all", "action-scoped taint.trust_overrides entry without source_match", "pipelock run applies it on reload", "standalone pipelock mcp proxy reads taint config only at startup", "restart", "history"} {
				if !strings.Contains(log.String(), want) {
					t.Errorf("operator log missing %q: %s", want, log.String())
				}
			}
			if rec.RiskSnapshot().Level != session.TaintExternalHostile {
				t.Fatal("diagnostic cleared hostile state")
			}
		})
	}
}

func TestMCPTaintDiagnostics_RecoveryParity(t *testing.T) {
	cfg := config.Defaults()
	var guidance string
	for _, d := range cfg.MCPTaintDiagnostics() {
		if d.Field == "taint.mcp_recovery" {
			guidance = d.Message
		}
	}
	docs, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	// The same canonical recovery paragraph belongs in config, logs, and docs.
	if guidance == "" || !strings.Contains(string(docs), guidance) {
		t.Fatal("config recovery and docs differ")
	}
	var log bytes.Buffer
	mcpTaintBlockMessage(taintDecision{}, &log)
	if !strings.Contains(log.String(), guidance) {
		t.Fatal("operator recovery and config differ")
	}

	for _, want := range []string{"Every MCP session", "runtime trust grants are rejected for all", "action-scoped taint.trust_overrides entry without source_match", "pipelock run applies it on reload", "standalone pipelock mcp proxy reads taint config only at startup"} {
		if !strings.Contains(guidance, want) {
			t.Errorf("recovery omitted %q", want)
		}
	}
}

func TestMCPTaintDiagnostics_RecorderRemedies(t *testing.T) {
	cfg := config.Defaults()
	for _, binding := range []string{"stdio_subprocess", "stdio_http", "stdio_ws", "listener_principal", "listener_legacy", "listener_token", "listener_stateless"} {
		t.Run(binding, func(t *testing.T) {
			var out bytes.Buffer
			reportMCPTaint(&out, MCPProxyOpts{TaintCfg: &cfg.Taint}, nil, binding)
			text := out.String()
			if strings.Contains(text, "persistent") {
				t.Error("recorder scope implies restart persistence")
			}
			want := "enable session_profiling.enabled and restart"
			if strings.HasPrefix(binding, "listener_") {
				want = "restart the listener with session_profiling.enabled; also check listener state capacity"
			}
			if !strings.Contains(text, want) {
				t.Errorf("missing binding-specific remedy %q: %s", want, text)
			}
		})
	}
}

func TestMCPTaintDiagnostics_DocsPreserveHeadlessAndHTTPOverrideScope(t *testing.T) {
	docs, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(docs)), " ")
	start := strings.Index(text, "### Common taint decisions")
	end := strings.Index(text, "### Trust overrides")
	if start < 0 || end <= start {
		t.Fatal("common taint documentation missing")
	}
	section := text[start:end]
	for _, want := range []string{
		"the agent sends chat requests through the forward proxy",
		"When taint policy returns `decision: \"ask\"`, Pipelock can only prompt an operator if it was started with an interactive terminal.",
		"The prompt appears in the terminal running Pipelock and accepts allow/block input.",
		"In headless deployments such as Docker or Kubernetes, there is no terminal to ask, so `ask` fails closed and blocks; configure an allowlist, a narrow trust override, or `taint.policy: permissive` during tuning, then retry the request.",
		"Configured overrides accept risk only within their matching scope and expiry (for MCP, only the action scope can match)",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("common taint guidance omitted %q", want)
		}
	}
	headless := strings.Index(section, "When taint policy returns")
	mcp := strings.Index(section, config.MCPTaintRecoveryGuidance)
	if headless < 0 || mcp <= headless {
		t.Error("generic headless guidance must precede the unchanged MCP-specific paragraph")
	}
}
