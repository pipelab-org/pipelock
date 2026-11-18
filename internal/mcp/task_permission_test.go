// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	gobwasutil "github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/session"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type taskApprovalOutput struct {
	input *io.PipeWriter
	first string
	count int
}

func (w *taskApprovalOutput) Write(p []byte) (int, error) {
	const prompt = "enter y "
	if _, text, ok := strings.Cut(string(p), prompt); ok {
		challenge, _, _ := strings.Cut(text, ".")
		w.count++
		if w.count == 1 {
			w.first = challenge
		}
		// Approve the first operation. Offer the same response again even
		// though the second operation has different arguments.
		if _, err := io.WriteString(w.input, "y "+w.first+"\n"); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func TestStdioTaskPermissionApprovalIsSingleUseForExactArguments(t *testing.T) {
	t.Parallel()
	r, w := io.Pipe()
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	prompts := &taskApprovalOutput{input: w}
	approver := hitl.New(1, hitl.WithInput(r), hitl.WithOutput(prompts), hitl.WithTerminal(true))
	defer approver.Close()

	cfg := config.Defaults()
	rec := &taintRecorder{}
	rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
	opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), Rec: rec, TaintCfg: &cfg.Taint, Approver: approver}
	first := principalControlToolCall(1, "write_file", `{"path":"/workspace/status.txt","content":"ready"}`)
	second := principalControlToolCall(2, "write_file", `{"path":"/workspace/status.txt","content":"changed"}`)
	in := strings.NewReader(string(first) + "\n" + string(second) + "\n")
	var out bytes.Buffer
	blocked := make(chan BlockedRequest, 2)
	ForwardScannedInput(transport.NewStdioReader(in), transport.NewStdioWriter(&out), io.Discard,
		config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
	denial := <-blocked
	if bytes.Count(out.Bytes(), []byte("\n")) != 1 || !bytes.Contains(out.Bytes(), []byte("ready")) || prompts.count != 2 ||
		!strings.Contains(denial.ErrorMessage, "task_approval_unconfirmed") {
		t.Fatalf("prompts=%d upstream=%s denial=%q", prompts.count, out.String(), denial.ErrorMessage)
	}
}

func TestStdioTaskPermissionNonTerminalApprover(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	rec := &taintRecorder{}
	rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
	approver := hitl.New(1, hitl.WithTerminal(false))
	defer approver.Close()
	opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), Rec: rec, TaintCfg: &cfg.Taint, Approver: approver}
	msg := principalControlToolCall(1, "write_file", `{"path":"/workspace/status.txt","content":"ready"}`)
	var out bytes.Buffer
	blocked := make(chan BlockedRequest, 1)
	ForwardScannedInput(transport.NewStdioReader(strings.NewReader(string(msg)+"\n")), transport.NewStdioWriter(&out), io.Discard,
		config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
	denial := <-blocked
	if out.Len() != 0 || !strings.Contains(denial.ErrorMessage, "task_approval_unavailable") ||
		!strings.Contains(denial.ErrorMessage, "not a terminal") {
		t.Fatalf("upstream=%s denial=%q", out.String(), denial.ErrorMessage)
	}
}

func TestStdioTaskPermissionClassifiesCallsAfterExposure(t *testing.T) {
	t.Parallel()
	const safeReadReason = "taint_safe_read_only_action"
	for _, tc := range []struct {
		name       string
		tool       string
		args       string
		finding    session.HostileFindingKind
		wantClass  session.ActionClass
		wantReason string
	}{
		{"read", "read_file", `{"path":"/workspace/notes.txt"}`, session.FindingDLP, session.ActionClassRead, safeReadReason},
		{"list", "list_directory", `{"path":"/workspace"}`, session.FindingDLP, session.ActionClassRead, safeReadReason},
		{"search", "search_files", `{"query":"notes"}`, session.FindingDLP, session.ActionClassRead, safeReadReason},
		{"get", "get_file", `{"path":"/workspace/notes.txt"}`, session.FindingDLP, session.ActionClassRead, safeReadReason},
		{"get_status", "get_status", `{"path":"/workspace/status.txt"}`, session.FindingDLP, session.ActionClassRead, safeReadReason},
		{"fetch", "fetch_page", `{"url":"https://docs.vendor.example/guide"}`, session.FindingDLP, session.ActionClassBrowse, safeReadReason},
		{"browse", "browse_docs", `{"url":"https://docs.vendor.example/guide"}`, session.FindingDLP, session.ActionClassBrowse, safeReadReason},
		{"delegation", "delegate_task", `{"task":"summarize","recipient":"other-agent"}`, session.FindingDLP, session.ActionClassUnknown, session.TaskPermissionRequired},
		{"unknown", "frobnicate_widget", `{"id":"1"}`, session.FindingDLP, session.ActionClassUnknown, session.TaskPermissionRequired},
		// Exec arguments take precedence over a read name, even though main classifies this as a read.
		{"read_with_exec_args", "read_file", `{"path":"/workspace/notes.txt","command":"echo test"}`, session.FindingDLP, session.ActionClassExec, session.TaskPermissionRequired},
		{"browse_with_mutating_args", "browse_docs", `{"url":"https://docs.vendor.example/guide","method":"POST"}`, session.FindingDLP, session.ActionClassPublish, session.TaskPermissionRequired},
		{"upload", "upload_file", `{"path":"/workspace/notes.txt"}`, session.FindingDLP, session.ActionClassPublish, session.TaskPermissionRequired},
		{"clean_upload", "upload_file", `{"path":"/workspace/notes.txt"}`, "", session.ActionClassPublish, "trusted_or_allowlisted_context"},
		{"clean_write", "write_file", `{"path":"/workspace/status.txt","content":"ready"}`, "", session.ActionClassWrite, "trusted_or_allowlisted_context"},
		{"wording_only", "delegate_task", `{"task":"summarize"}`, session.FindingWording, session.ActionClassUnknown, "no_taint_escalation_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Taint.FailSafeClassification = false
			rec := &taintRecorder{}
			approver := hitl.New(1, hitl.WithTerminal(false))
			defer approver.Close()
			opts := MCPProxyOpts{Scanner: testScannerWithAction(t, config.ActionWarn), Rec: rec, TaintCfg: &cfg.Taint, TaintExternalSource: true, Approver: approver}
			if tc.finding != "" {
				observeMCPResponseFindings(opts, []session.HostileFindingKind{tc.finding})
			}
			decision := evaluateMCPTaint(opts, tc.tool, tc.args)
			if decision.ActionClass != tc.wantClass || decision.Result.Reason != tc.wantReason {
				t.Errorf("class=%s reason=%q, want class=%s reason=%q", decision.ActionClass, decision.Result.Reason, tc.wantClass, tc.wantReason)
			}
			msg := principalControlToolCall(1, tc.tool, tc.args)
			frame := string(msg) + "\n"
			var sent bytes.Buffer
			blocked := make(chan BlockedRequest, 1)
			ForwardScannedInput(transport.NewStdioReader(strings.NewReader(frame)), transport.NewStdioWriter(&sent), io.Discard,
				config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
			denial, refused := <-blocked
			if tc.wantReason == session.TaskPermissionRequired {
				if sent.Len() != 0 || !refused || !strings.Contains(denial.ErrorMessage, "task_approval_unavailable") {
					t.Errorf("upstream=%s denial=%q, want zero upstream bytes and task_approval_unavailable", sent.String(), denial.ErrorMessage)
				}
			} else if sent.String() != frame || refused {
				t.Errorf("upstream=%s denial=%q, want one unmodified frame and no denial", sent.String(), denial.ErrorMessage)
			}
		})
	}
}

type taskPermissionTestStore struct{ rec session.Recorder }

func (s taskPermissionTestStore) GetOrCreate(string) session.Recorder { return s.rec }
func (taskPermissionTestStore) Delete(string)                         {}

type httpTaskPermissionRecorder struct {
	listenerDiagnosisRecorder
	subject string
	action  session.TaskAction
	rotated bool
	checks  int
}

func (r *httpTaskPermissionRecorder) BindTaskSubject(subject string) { r.subject = subject }

func (r *httpTaskPermissionRecorder) TaskPolicySnapshot(subject string, action session.TaskAction) (session.SessionRisk, session.TaskContext, bool) {
	r.checks++
	task := session.TaskContext{CurrentTaskID: "original-task"}
	if r.rotated {
		task.CurrentTaskID = "next-task"
	}
	return r.RiskSnapshot(), task, subject != "" && subject == r.subject && action == r.action && !r.rotated
}

func TestMCPTaskReleaseRequiresAdmittedCallableIdentity(t *testing.T) {
	cfg := config.Defaults()
	rec := &listenerDiagnosisRecorder{}
	rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
	opts := MCPProxyOpts{Rec: rec, TaintCfg: &cfg.Taint}
	admitted := taintDecision{taskAction: mcpTaskAction(opts, ParseMCPFrame([]byte(deferKillTestCall)))}
	if reason := mcpTaskReleaseRefusal(opts, MCPFrame{}, admitted, false); !strings.Contains(reason, session.TaskPermissionRequired) {
		t.Errorf("release refusal = %q, want %s", reason, session.TaskPermissionRequired)
	}
	metadata := ParseMCPFrame([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if reason := mcpTaskReleaseRefusal(opts, metadata, taintDecision{}, false); reason != "" {
		t.Errorf("metadata release refusal = %q, want allow", reason)
	}
}

func TestDeferredHTTPReleaseChecksTaskPermissionWithoutAuthorityVerifier(t *testing.T) {
	for _, tc := range []struct {
		name      string
		grant     bool
		wantCalls int32
		wantReply string
	}{
		{"missing_grant", false, 0, session.TaskPermissionRequired},
		{"exact_grant", true, 1, `"result"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			rec := &httpTaskPermissionRecorder{}
			run := startHTTPDeferRun(t, deferKillTestController(), func(opts *MCPProxyOpts) {
				opts.Store = taskPermissionTestStore{rec: rec}
				opts.TaintCfg = &cfg.Taint
				opts.ServerBinding = "test-server"
				if tc.grant {
					rec.action = mcpTaskAction(*opts, ParseMCPFrame([]byte(deferKillTestCall)))
				}
			})
			defer run.stop(t)
			rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
			held := run.manager.Snapshot()[0]
			if err := run.manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceApproval); err != nil {
				t.Fatal(err)
			}
			if got, reply := run.calls.Load(), run.stdout.String(); got != tc.wantCalls || !strings.Contains(reply, tc.wantReply) {
				t.Fatalf("upstream requests = %d, want %d. Response = %s, want %q", got, tc.wantCalls, reply, tc.wantReply)
			}
		})
	}
}

func TestHTTPTaskPermissionRechecksAtSend(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rotate    bool
		wantCalls int32
		wantReply string
	}{
		{"rotated_task", true, 0, session.TaskApprovalStale},
		{"current_grant", false, 1, `"result"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, calls := countingUpstream(t)
			cfg := config.Defaults()
			rec := &httpTaskPermissionRecorder{}
			rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint,
				Store: taskPermissionTestStore{rec: rec}, ServerBinding: "test-server",
				ContractLoaderFn: func() *contractruntime.Loader {
					// The input gate and its finalizer have both checked the grant.
					// This is the per-send upstream gate, before the send lock.
					if tc.rotate && rec.checks >= 2 {
						rec.rotated = true
					}
					return nil
				},
			}
			rec.action = mcpTaskAction(opts, ParseMCPFrame([]byte(deferKillTestCall)))
			var output bytes.Buffer
			if err := RunHTTPProxy(t.Context(), strings.NewReader(deferKillTestCall), &output, io.Discard, upstream.URL, nil, opts); err != nil {
				t.Fatal(err)
			}
			if got := calls.Load(); got != tc.wantCalls || !strings.Contains(output.String(), tc.wantReply) {
				t.Fatalf("upstream requests = %d, want %d. Response = %s, want %q", got, tc.wantCalls, output.String(), tc.wantReply)
			}
		})
	}
}

func TestTaskPermissionRefusesHostileCallsAcrossMCPTransports(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"stdio_to_http", "http_listener", "websocket"} {
		t.Run(mode, func(t *testing.T) {
			var deliveries atomic.Int32
			answer := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "websocket" {
					conn, _, _, err := (ws.HTTPUpgrader{}).Upgrade(r, w)
					if err != nil {
						return
					}
					defer func() { _ = conn.Close() }()
					if _, _, err := gobwasutil.ReadClientData(conn); err == nil {
						deliveries.Add(1)
						_ = gobwasutil.WriteServerMessage(conn, ws.OpText, answer)
					}
					return
				}
				if r.Method == http.MethodPost {
					deliveries.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(answer)
					return
				}
				w.WriteHeader(http.StatusMethodNotAllowed)
			}))
			defer upstream.Close()

			rec := &listenerDiagnosisRecorder{}
			rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingToolPoisoning}))
			cfg := config.Defaults()
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint,
				Store: taskPermissionTestStore{rec: rec},
			}
			msg := principalControlToolCall(1, "frobnicate_widget", `{"id":"1"}`)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var output lockedHTTPBuffer
			switch mode {
			case "stdio_to_http":
				if err := RunHTTPProxy(ctx, strings.NewReader(string(msg)+"\n"), &output, io.Discard, upstream.URL, nil, opts); err != nil {
					t.Fatal(err)
				}
			case "http_listener":
				opts.ListenerBearerToken = principalStateTestBearer
				opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
					return ListenerPrincipal{Provider: "test", Subject: "operator-test-agent"}, nil
				}
				baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
				_, response := mustPrincipalControlRPC(t, baseURL, principalStateTestBearer, msg)
				_, _ = output.Write([]byte(response))
			case "websocket":
				r, w := io.Pipe()
				done := make(chan error, 1)
				go func() { done <- RunWSProxy(ctx, r, &output, io.Discard, wsURL(upstream), opts) }()
				defer func() { _ = w.Close() }()
				if _, err := w.Write(append(msg, '\n')); err != nil {
					t.Fatal(err)
				}
				testwait.For(t, time.Second, func() bool { return output.contains("task_approval_unavailable") }, "MCP WebSocket refusal")
				_ = w.Close()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
			if !output.contains("task_approval_unavailable") || deliveries.Load() != 0 {
				t.Fatalf("upstream deliveries=%d response=%s", deliveries.Load(), output.String())
			}
		})
	}
}
