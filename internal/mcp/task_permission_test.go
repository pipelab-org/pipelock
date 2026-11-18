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
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/session"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type taskApprovalOutput struct {
	input        *io.PipeWriter
	first        string
	count        int
	beforeAnswer func()
}

func (w *taskApprovalOutput) Write(p []byte) (int, error) {
	const prompt = "enter y "
	if _, text, ok := strings.Cut(string(p), prompt); ok {
		challenge, _, _ := strings.Cut(text, ".")
		w.count++
		if w.count == 1 {
			w.first = challenge
		}
		if w.beforeAnswer != nil {
			w.beforeAnswer()
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
	subject  string
	action   session.TaskAction
	rotated  bool
	checks   int
	expireAt int
}

func (r *httpTaskPermissionRecorder) BindTaskSubject(subject string) { r.subject = subject }

func (r *httpTaskPermissionRecorder) TaskPolicySnapshot(subject string, action session.TaskAction) (session.SessionRisk, session.TaskContext, bool) {
	r.checks++
	matched := subject != "" && subject == r.subject && action == r.action && !r.rotated
	if r.expireAt > 0 && r.checks >= r.expireAt {
		matched = false
	}
	return r.RiskSnapshot(), r.TaskSnapshot(), matched
}

func (r *httpTaskPermissionRecorder) TaskSnapshot() session.TaskContext {
	task := session.TaskContext{CurrentTaskID: "original-task"}
	if r.rotated {
		task.CurrentTaskID = "next-task"
	}
	return task
}

func (*httpTaskPermissionRecorder) RuntimeTrustOverrides() []session.TrustOverride { return nil }

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
	for _, mode := range []string{"stdio", "stdio_to_http", "http_listener", "websocket"} {
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct {
				name, answer, reason string
				terminal, timeout    bool
			}{
				{name: "unavailable", reason: "task_approval_unavailable"},
				{name: "declined", answer: "n\n", terminal: true, reason: "task_approval_denied"},
				{name: "timed_out", timeout: true, terminal: true, reason: "task_approval_timeout"},
				{name: "input_lost", terminal: true, reason: "task_approval_input_lost"},
				{name: "unconfirmed", answer: "y\n", terminal: true, reason: "task_approval_unconfirmed"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					var input io.Reader = strings.NewReader(tc.answer)
					if tc.timeout {
						r, w := io.Pipe()
						t.Cleanup(func() {
							_ = w.Close()
							_ = r.Close()
						})
						input = r
					}
					var approver *hitl.Approver
					if tc.terminal {
						approver = hitl.New(1, hitl.WithTerminal(true), hitl.WithInput(input), hitl.WithOutput(io.Discard))
						t.Cleanup(approver.Close)
					}
					observed := &allReceipts{}
					emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, observed.observe)
					rec := &listenerDiagnosisRecorder{}
					rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingToolPoisoning}))
					cfg := config.Defaults()
					opts := MCPProxyOpts{
						Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Approver: approver,
						Store: taskPermissionTestStore{rec: rec}, Rec: rec, ReceiptEmitter: emitter,
					}
					msg := principalControlToolCall(1, "frobnicate_widget", `{"id":"1"}`)
					response, deliveries := runTaskPermissionMCPCall(t, mode, tc.reason, msg, opts)
					if !strings.Contains(response, tc.reason) || deliveries != 0 {
						t.Fatalf("upstream deliveries=%d response=%q, want zero deliveries and %q", deliveries, response, tc.reason)
					}
					if records := observed.snapshot(); len(records) != 1 || records[0].Verdict != config.ActionBlock || records[0].Pattern != tc.reason {
						t.Errorf("receipts = %+v, want one block with %q", records, tc.reason)
					}
				})
			}
		})
	}
}

func runTaskPermissionMCPCall(t *testing.T, mode, reason string, msg []byte, opts MCPProxyOpts) (string, int) {
	t.Helper()
	if mode == "stdio" {
		opts.Transport = deferred.SurfaceMCPStdio
		var sent bytes.Buffer
		blocked := make(chan BlockedRequest, 1)
		ForwardScannedInput(transport.NewStdioReader(strings.NewReader(string(msg)+"\n")),
			transport.NewStdioWriter(&sent), io.Discard, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
		denial := <-blocked
		return denial.ErrorMessage, bytes.Count(sent.Bytes(), []byte("\n"))
	}

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
	t.Cleanup(upstream.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
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
		defer func() { _ = w.Close() }()
		done := make(chan error, 1)
		go func() { done <- RunWSProxy(ctx, r, &output, io.Discard, wsURL(upstream), opts) }()
		if _, err := w.Write(append(msg, '\n')); err != nil {
			t.Fatal(err)
		}
		testwait.For(t, 3*time.Second, func() bool { return output.contains(reason) || output.contains(`"result"`) }, "MCP WebSocket response")
		_ = w.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown transport %q", mode)
	}
	return output.String(), int(deliveries.Load())
}

func TestMCPTaskPermissionRefusesIfApprovalOutlivesTask(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	rec := &httpTaskPermissionRecorder{}
	rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
	r, w := io.Pipe()
	t.Cleanup(func() {
		_ = w.Close()
		_ = r.Close()
	})
	prompt := &taskApprovalOutput{input: w, beforeAnswer: func() { rec.rotated = true }}
	approver := hitl.New(1, hitl.WithInput(r), hitl.WithOutput(prompt), hitl.WithTerminal(true))
	t.Cleanup(approver.Close)
	opts := MCPProxyOpts{
		Scanner: testScannerForHTTP(t), Rec: rec, TaintCfg: &cfg.Taint, Approver: approver,
		ServerBinding: "test-server", ServerRevision: "v1", TaskOperatorAPI: true, taskSubject: "verified-worker",
	}
	response, deliveries := runTaskPermissionMCPCall(t, "stdio", session.TaskApprovalStale, []byte(deferKillTestCall), opts)
	if !strings.Contains(response, "the task changed while approval was pending") || deliveries != 0 || prompt.count != 1 {
		t.Fatalf("response=%q deliveries=%d prompts=%d, want refusal of the stale approval", response, deliveries, prompt.count)
	}
}

func TestMCPTaskPermissionRefusesChangedRelease(t *testing.T) {
	t.Parallel()
	const missing = session.TaskPermissionRequired + " (the action needs a current task permission or approval before release)"
	const redirected = session.TaskPermissionRequired + " (a tool-policy redirect changes the approved destination)"
	for _, tc := range []struct {
		name, mode, policyAction, reason string
		expireAt                         int
	}{
		{"stdio_clean", "stdio", "", missing, 2},
		{"stdio_warn", "stdio", config.ActionWarn, missing, 2},
		{"stdio_redirect", "stdio", config.ActionRedirect, redirected, 0},
		{"bridge_input_finalizer", "stdio_to_http", "", missing, 2},
		{"bridge_redirect", "stdio_to_http", config.ActionRedirect, redirected, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			rec := &httpTaskPermissionRecorder{expireAt: tc.expireAt}
			rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Rec: rec,
				Store: taskPermissionTestStore{rec: rec}, ServerBinding: "test-server", taskSubject: "verified-worker",
			}
			msg := []byte(deferKillTestCall)
			rec.BindTaskSubject(opts.taskSubject)
			rec.action = mcpTaskAction(opts, ParseMCPFrame(msg))
			if tc.policyAction != "" {
				opts.PolicyCfg = policy.New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: []config.ToolPolicyRule{
					{Name: "route-tool", ToolPattern: "^" + ParseMCPFrame(msg).ToolCallName + "$", Action: tc.policyAction, RedirectProfile: "local"},
				}})
			}
			response, deliveries := runTaskPermissionMCPCall(t, tc.mode, tc.reason, msg, opts)
			if !strings.Contains(response, tc.reason) || deliveries != 0 {
				t.Fatalf("response=%q deliveries=%d, want %q and no delivery", response, deliveries, tc.reason)
			}
		})
	}
}

func TestHTTPTaskPermissionBridgeRefusesAtSendWithoutNotificationReply(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		notification bool
		writeFails   bool
	}{
		{name: "request"},
		{name: "notification", notification: true},
		{name: "reply_write_error", writeFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, calls := countingUpstream(t)
			cfg := config.Defaults()
			rec := &httpTaskPermissionRecorder{expireAt: 3}
			rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
			observed := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, observed.observe)
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint,
				Store: taskPermissionTestStore{rec: rec}, ServerBinding: "test-server", ReceiptEmitter: emitter, RequireReceipts: true,
			}
			frame := ParseMCPFrame([]byte(deferKillTestCall))
			msg := deferKillTestCall
			if tc.notification {
				msg = makeRequest(1, methodToolsCall, map[string]any{"name": frame.ToolCallName, "arguments": frame.Args})
				msg = strings.Replace(msg, `"id":1,`, "", 1)
				if len(ParseMCPFrame([]byte(msg)).ID) != 0 {
					t.Fatal("fixture still has a request ID")
				}
			}
			rec.action = mcpTaskAction(opts, ParseMCPFrame([]byte(msg)))
			var output, logs bytes.Buffer
			var client io.Writer = &output
			if tc.writeFails {
				client = &scanFailingWriter{err: io.ErrClosedPipe}
			}
			if err := RunHTTPProxy(t.Context(), strings.NewReader(msg+"\n"), client, &logs, upstream.URL, nil, opts); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 0 || rec.checks != 3 {
				t.Fatalf("upstream deliveries=%d permission checks=%d output=%q, want refusal at send", calls.Load(), rec.checks, output.String())
			}
			switch {
			case tc.notification:
				if output.Len() != 0 {
					t.Errorf("notification received a JSON-RPC reply: %q", output.String())
				}
			case tc.writeFails:
				if !strings.Contains(logs.String(), "failed to send task refusal") {
					t.Errorf("denial write failure was not logged: %q", logs.String())
				}
			default:
				if !strings.Contains(output.String(), session.TaskPermissionRequired) {
					t.Errorf("response = %q, want task permission refusal", output.String())
				}
			}
			records := observed.snapshot()
			if len(records) != 2 || records[0].ActionID != records[1].ActionID || records[1].Verdict != config.ActionBlock ||
				!strings.Contains(records[1].Pattern, "reason="+session.TaskPermissionRequired) {
				t.Errorf("receipts = %+v, want the intent closed by a task-permission block", records)
			}
		})
	}
}

func TestMCPTaskPermissionExplainsOperatorGrant(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	rec := &listenerDiagnosisRecorder{}
	rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
	opts := MCPProxyOpts{
		Scanner: testScannerForHTTP(t), Rec: rec, TaintCfg: &cfg.Taint,
		ServerBinding: "test-server", ServerRevision: "v1", TaskOperatorAPI: true, taskSubject: "verified-worker",
	}
	msg := []byte(deferKillTestCall)
	response, deliveries := runTaskPermissionMCPCall(t, "stdio", "task_approval_unavailable", msg, opts)
	if deliveries != 0 || !strings.Contains(response, "POST /api/v1/sessions/{key}/task") ||
		!strings.Contains(response, "destination test-server/v1, digest "+mcpTaskAction(opts, ParseMCPFrame(msg)).Digest) {
		t.Fatalf("response=%q deliveries=%d, want refusal with the operator route and exact action", response, deliveries)
	}
}

func TestMCPTaskReleaseRefusesMissingCallableWhenTaintEnabled(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		enabled bool
		want    string
	}{
		{"enabled", true, session.TaskPermissionRequired + " (the action has no callable identity)"},
		{"disabled", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Taint.Enabled = tc.enabled
			rec := &listenerDiagnosisRecorder{}
			rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
			opts := MCPProxyOpts{Rec: rec, TaintCfg: &cfg.Taint}
			frame := ParseMCPFrame([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`))
			if got := mcpTaskReleaseRefusal(opts, frame, taintDecision{}, false); got != tc.want {
				t.Errorf("release refusal = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeferredStdioTaskPermissionRefusesReleaseAfterHostileExposure(t *testing.T) {
	t.Parallel()
	manager := newDeferKillManager(t)
	observed := &resolutionReceipts{}
	emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, observed.observe)
	rules := deferApprovalPolicy(config.DeferResolverProfile{})
	rules.Rules[0].ResolutionPolicy.ResolverProfile = ""
	cfg := config.Defaults()
	rec := &listenerDiagnosisRecorder{}
	opts := MCPProxyOpts{
		Scanner: testInputScanner(t), PolicyCfg: rules, DeferManager: manager, ReceiptEmitter: emitter,
		Transport: deferred.SurfaceMCPStdio, Rec: rec, TaintCfg: &cfg.Taint,
	}
	input, send := io.Pipe()
	var upstream syncBuffer
	blocked := make(chan BlockedRequest, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardScannedInput(transport.NewStdioReader(input), transport.NewStdioWriter(&upstream), io.Discard,
			config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
	}()
	t.Cleanup(func() {
		_ = send.Close()
		<-done
	})
	if _, err := io.WriteString(send, deferKillTestCall); err != nil {
		t.Fatal(err)
	}
	testwait.For(t, 5*time.Second, func() bool { return len(manager.Snapshot()) == 1 }, "deferred stdio action")
	held := manager.Snapshot()[0]
	rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
	if err := manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceApproval); err != nil {
		t.Fatal(err)
	}
	select {
	case denial := <-blocked:
		if denial.ErrorCode != -32002 || denial.ErrorMessage != "pipelock: deferred action denied" {
			t.Errorf("deferred refusal = %d %q", denial.ErrorCode, denial.ErrorMessage)
		}
	default:
		t.Error("deferred task denial produced no client refusal")
	}
	if upstream.String() != "" {
		t.Errorf("deferred action was delivered upstream: %q", upstream.String())
	}
	assertTerminalJournal(t, manager, held.DeferID, deferred.StateResolvedBlock, deferred.SourceApproval)
	if records := observed.snapshot(); len(records) != 1 || records[0].Verdict != config.ActionBlock {
		t.Errorf("resolution receipts = %+v, want one final block", records)
	}
}
