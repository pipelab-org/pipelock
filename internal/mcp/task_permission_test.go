// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	"github.com/luckyPipewrench/pipelock/internal/receipt"
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

func TestStdioTaskPermissionBrowserAndDelegation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, tool, args string
		allowHostile     bool
	}{
		{"navigate", "browser_navigate", `{"url":"https://docs.vendor.example/guide"}`, true},
		{"snapshot", "browser_snapshot", `{}`, true},
		{"list_tabs", "browser_tabs", `{"action":"list"}`, true},
		{"click", "browser_click", `{"element":"Details","ref":"e1"}`, false},
		{"type", "browser_type", `{"element":"Search","ref":"e1","text":"notes"}`, false},
		{"evaluate", "browser_evaluate", `{"function":"() => document.title"}`, false},
		{"close_tab", "browser_tabs", `{"action":"close","index":0}`, false},
		{"screenshot_file", "browser_take_screenshot", `{"filename":"snapshot.png"}`, false},
		{"retry", "retry_with_browser_use_agent", `{"task":"summarize"}`, false},
		{"open_subtask", "open_subtask", `{"task":"summarize"}`, false},
		{"spawn_subagent", "spawn_subagent", `{"task":"summarize"}`, false},
		{"delegate_run", "delegate_run", `{"task":"summarize"}`, false},
		{"list_subagents", "list_subagents", `{}`, true},
		{"prefetch", "prefetch_cache", `{}`, true},
		{"browser_namespace_only", "mcp__browser__frobnicate", `{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, hostile := range []bool{false, true} {
				t.Run("hostile="+strconv.FormatBool(hostile), func(t *testing.T) {
					cfg := config.Defaults()
					approver := hitl.New(1, hitl.WithTerminal(false))
					defer approver.Close()
					opts := MCPProxyOpts{
						Scanner: testScannerWithAction(t, config.ActionWarn), Rec: &taintRecorder{},
						TaintCfg: &cfg.Taint, TaintExternalSource: true, Approver: approver,
					}
					if hostile {
						observeMCPResponseFindings(opts, []session.HostileFindingKind{session.FindingDLP})
					}
					frame := string(principalControlToolCall(1, tc.tool, tc.args)) + "\n"
					var sent bytes.Buffer
					blocked := make(chan BlockedRequest, 1)
					ForwardScannedInput(transport.NewStdioReader(strings.NewReader(frame)), transport.NewStdioWriter(&sent), io.Discard,
						config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
					denial, refused := <-blocked
					if !hostile || tc.allowHostile {
						if sent.String() != frame || refused {
							t.Errorf("upstream=%s denial=%q, want one unmodified frame and no denial", sent.String(), denial.ErrorMessage)
						}
					} else if sent.Len() != 0 || !refused || !strings.Contains(denial.ErrorMessage, "task_approval_unavailable") {
						t.Errorf("upstream=%s denial=%q, want zero upstream bytes and task_approval_unavailable", sent.String(), denial.ErrorMessage)
					}
				})
			}
		})
	}
}

func TestStdioTaskPermissionBrowserClickExactGrant(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	rec := &httpTaskPermissionRecorder{}
	approver := hitl.New(1, hitl.WithTerminal(false))
	defer approver.Close()
	opts := MCPProxyOpts{
		Scanner: testScannerForHTTP(t), Rec: rec, TaintCfg: &cfg.Taint, TaintExternalSource: true,
		Approver: approver, ServerBinding: "test-server", taskSubject: "test-subject",
	}
	session.BindTaskSubject(rec, opts.taskSubject)
	observeMCPResponseFindings(opts, []session.HostileFindingKind{session.FindingDLP})
	exact := principalControlToolCall(1, "browser_click", `{"element":"Details","ref":"e1"}`)
	other := principalControlToolCall(2, "browser_click", `{"element":"Summary","ref":"e2"}`)
	rec.action = mcpTaskAction(opts, ParseMCPFrame(exact))
	var sent bytes.Buffer
	blocked := make(chan BlockedRequest, 2)
	in := strings.NewReader(string(exact) + "\n" + string(other) + "\n")
	ForwardScannedInput(transport.NewStdioReader(in), transport.NewStdioWriter(&sent), io.Discard,
		config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
	denial := <-blocked
	if sent.String() != string(exact)+"\n" || string(denial.ID) != "2" || !strings.Contains(denial.ErrorMessage, "task_approval_unavailable") {
		t.Fatalf("upstream=%s denial=%q, want only the exact granted call", sent.String(), denial.ErrorMessage)
	}
}

type taskPermissionTestStore struct{ rec session.Recorder }

func (s taskPermissionTestStore) GetOrCreate(string) session.Recorder { return s.rec }
func (taskPermissionTestStore) Delete(string)                         {}

type httpTaskPermissionRecorder struct {
	listenerDiagnosisRecorder
	subject  string
	action   session.TaskAction
	rotated  atomic.Bool
	checks   int
	expireAt int
	expired  atomic.Bool
}

func (r *httpTaskPermissionRecorder) BindTaskSubject(subject string) { r.subject = subject }

func (r *httpTaskPermissionRecorder) TaskPolicySnapshot(subject string, action session.TaskAction) (session.SessionRisk, session.TaskContext, bool) {
	r.checks++
	matched := subject != "" && subject == r.subject && action == r.action && !r.rotated.Load() && !r.expired.Load()
	if r.expireAt > 0 && r.checks >= r.expireAt {
		matched = false
	}
	return r.RiskSnapshot(), r.TaskSnapshot(), matched
}

func (r *httpTaskPermissionRecorder) TaskSnapshot() session.TaskContext {
	task := session.TaskContext{CurrentTaskID: "original-task"}
	rotated := r.rotated.Load()
	if rotated {
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

func TestMCPTaskReleaseRefusesNonAllowDecisionAfterHostileExposure(t *testing.T) {
	read := ParseMCPFrame([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"notes.txt"}}}`))
	for _, tc := range []struct {
		name       string
		failSafe   bool
		wantRefuse bool
	}{
		// Admitted while clean; after a hostile finding the fail-safe
		// low-confidence read no longer evaluates to allow, so release
		// must refuse it instead of falling through.
		{"fail_safe_low_confidence_read", true, true},
		{"ordinary_read", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Taint.FailSafeClassification = tc.failSafe
			rec := &listenerDiagnosisRecorder{}
			rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
			opts := MCPProxyOpts{Rec: rec, TaintCfg: &cfg.Taint}
			reason := mcpTaskReleaseRefusal(opts, read, taintDecision{}, false)
			if got := reason != ""; got != tc.wantRefuse {
				t.Fatalf("release refusal = %q, want refusal %t", reason, tc.wantRefuse)
			}
			if tc.wantRefuse && !strings.Contains(reason, session.TaskPermissionRequired) {
				t.Fatalf("release refusal = %q, want %s", reason, session.TaskPermissionRequired)
			}
		})
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
			observed := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, observed.observe)
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint,
				Store: taskPermissionTestStore{rec: rec}, ServerBinding: "test-server", ReceiptEmitter: emitter,
				ContractLoaderFn: func() *contractruntime.Loader {
					// The input gate and its finalizer have both checked the grant.
					// This is the per-send upstream gate, before the send lock.
					if tc.rotate && rec.checks >= 2 {
						rec.rotated.Store(true)
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
			if !tc.rotate {
				records := observed.snapshot()
				if len(records) != 1 || records[0].Verdict != config.ActionAllow || records[0].DecisionPhase != "" {
					t.Errorf("receipts = %+v, want a single-phase allow after a successful task recheck", records)
				}
			}
		})
	}
}

func TestWSTaskPermissionRechecksAfterHandshake(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		expire     bool
		wantFrames int
		wantReply  string
	}{
		{"expired_during_handshake", true, 0, session.TaskPermissionRequired},
		{"current_grant", false, 1, `"result"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			rec := &httpTaskPermissionRecorder{}
			rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
			observed := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, observed.observe)
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint,
				Store: taskPermissionTestStore{rec: rec}, ServerBinding: "test-server",
				AuthorityVerifier: allowAuthorityVerifier(nil), AuthorityActor: "test-agent", ReceiptEmitter: emitter,
			}
			msg := []byte(strings.Replace(deferKillTestCall, `"arguments":`, `"_meta":{"com.pipelock/authority":"grant"},"arguments":`, 1))
			admitted, _, err := extractInboundMCPAuthority(msg)
			if err != nil {
				t.Fatal(err)
			}
			rec.action = mcpTaskAction(opts, ParseMCPFrame(admitted))
			response, deliveries := runTaskPermissionMCPCall(t, "websocket", msg, opts, func() {
				if tc.expire {
					rec.expired.Store(true)
				}
			})
			if deliveries != tc.wantFrames || !strings.Contains(response, tc.wantReply) {
				t.Fatalf("upstream frames=%d reply=%q, want %d and %q", deliveries, response, tc.wantFrames, tc.wantReply)
			}
			records := observed.snapshot()
			if !tc.expire {
				if len(records) != 1 || records[0].Verdict != config.ActionAllow || records[0].DecisionPhase != "" {
					t.Fatalf("receipts=%+v, want a single allow for the delivered frame", records)
				}
				return
			}
			if !strings.Contains(response, `"code":-32002`) {
				t.Errorf("response=%q, want task refusal code -32002", response)
			}
			if len(records) != 2 || records[0].ActionID != records[1].ActionID ||
				records[0].DecisionPhase != receipt.DecisionPhaseIntent || records[0].Verdict != config.ActionAllow ||
				records[1].DecisionPhase != receipt.DecisionPhaseOutcome || records[1].Verdict != config.ActionBlock ||
				records[1].TaintDecision != config.ActionBlock || records[1].TaintDecisionReason != session.TaskPermissionRequired {
				t.Errorf("receipts=%+v, want an allow intent closed by a task-permission block", records)
			}
		})
	}
}

func TestStdioTaskPermissionRechecksAfterReceipt(t *testing.T) {
	t.Parallel()
	for _, action := range []string{config.ActionAllow, config.ActionWarn} {
		t.Run(action, func(t *testing.T) {
			cfg := config.Defaults()
			rec := &httpTaskPermissionRecorder{}
			rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
			observed := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, func(r *receipt.Receipt) {
				observed.observe(r)
				if r.ActionRecord.Verdict == action {
					rec.rotated.Store(true)
				}
			})
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Rec: rec, ReceiptEmitter: emitter,
				ServerBinding: "test-server", taskSubject: "verified-worker", Transport: deferred.SurfaceMCPStdio,
				InputCfg: newHTTPInputCfg(config.ActionWarn), RequireReceipts: true,
			}
			msg := []byte(deferKillTestCall)
			rec.BindTaskSubject(opts.taskSubject)
			rec.action = mcpTaskAction(opts, ParseMCPFrame(msg))
			if action == config.ActionWarn {
				opts.PolicyCfg = policy.New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: []config.ToolPolicyRule{
					{Name: "warn-on-tool", ToolPattern: "^" + ParseMCPFrame(msg).ToolCallName + "$", Action: config.ActionWarn},
				}})
			}
			var sent, logs bytes.Buffer
			blocked := make(chan BlockedRequest, 1)
			ForwardScannedInput(transport.NewStdioReader(strings.NewReader(string(msg)+"\n")),
				transport.NewStdioWriter(&sent), &logs, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
			denial, refused := <-blocked
			if !rec.rotated.Load() || sent.Len() != 0 || !refused || denial.ErrorCode != -32002 || !strings.Contains(denial.ErrorMessage, session.TaskApprovalStale) {
				t.Fatalf("rotated=%t upstream=%q refusal=%q logs=%q, want no delivery and a stale-task refusal", rec.rotated.Load(), sent.String(), denial.ErrorMessage, logs.String())
			}
			records := observed.snapshot()
			if len(records) != 2 || records[1].Verdict != config.ActionBlock || records[1].TaintDecision != config.ActionBlock ||
				records[1].TaintDecisionReason != session.TaskApprovalStale {
				t.Fatalf("receipts=%+v, want the final receipt to record a stale-task block", records)
			}
		})
	}
}

func TestTaskPermissionReleaseRefusalReceiptUsesReleaseDecision(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"stdio", "stdio_to_http"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.Defaults()
			rec := &httpTaskPermissionRecorder{expireAt: 2}
			rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
			observed := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, observed.observe)
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Rec: rec, ReceiptEmitter: emitter,
				Store: taskPermissionTestStore{rec: rec}, ServerBinding: "test-server", taskSubject: "verified-worker",
			}
			msg := []byte(deferKillTestCall)
			rec.BindTaskSubject(opts.taskSubject)
			rec.action = mcpTaskAction(opts, ParseMCPFrame(msg))
			response, deliveries := runTaskPermissionMCPCall(t, mode, msg, opts)
			if rec.checks != 2 || deliveries != 0 || !strings.Contains(response, session.TaskPermissionRequired) {
				t.Fatalf("checks=%d deliveries=%d response=%q, want refusal on the second check", rec.checks, deliveries, response)
			}
			records := observed.snapshot()
			if len(records) != 1 || records[0].Verdict != config.ActionBlock {
				t.Fatalf("receipts=%+v, want one block", records)
			}
			if r := records[0]; r.TaintDecision != config.ActionBlock || r.TaintDecisionReason != session.TaskPermissionRequired {
				t.Errorf("receipt taint=%s/%s, want block/%s", r.TaintDecision, r.TaintDecisionReason, session.TaskPermissionRequired)
			}
		})
	}
}

func TestWSTaskPermissionHarnessSurfacesStartupError(t *testing.T) {
	t.Parallel()
	startupDialErr := errors.New("fixture startup dial failure")
	loader := mcpLiveLockLoader(t, contractruntime.ModeLive, mcpToolRule("r-allow", nil))
	for _, tc := range []struct {
		name string
		opts MCPProxyOpts
		want string
	}{
		{"startup_gate", MCPProxyOpts{ContractLoaderFn: func() *contractruntime.Loader { return loader }}, "contract upstream evaluation: scanner unavailable"},
		{"eager_dial", MCPProxyOpts{DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, startupDialErr }}, startupDialErr.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err := runTaskPermissionWS(ctx, []byte(deferKillTestCall), func(input io.Reader) error {
				return RunWSProxy(ctx, input, io.Discard, io.Discard, "ws://tools.vendor.example", tc.opts)
			}, func() { t.Error("startup failure reached response wait") })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("WebSocket harness error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestReverseTaskPermissionRechecksAfterHeaderDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name, wantReply string
		wantCalls       int32
	}{
		{"current", `"result"`, 1},
		{"rotated", session.TaskApprovalStale, 0},
		{"expired", session.TaskPermissionRequired, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const tool = "write_file"
			cfg := config.Defaults()
			rec := &httpTaskPermissionRecorder{}
			rec.ObserveRisk(session.ClassifyMCPResponseFindings(mcpTaintSourceKind, true, []session.HostileFindingKind{session.FindingDLP}))
			observed := &allReceipts{}
			emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, observed.observe)
			opts := paramContractOpts(t)
			opts.Store = taskPermissionTestStore{rec: rec}
			opts.TaintCfg = &cfg.Taint
			opts.ServerBinding = "test-server"
			opts.ReceiptEmitter = emitter
			opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
				return ListenerPrincipal{Provider: "test", Subject: "operator-test-agent"}, nil
			}
			body := currentWireBody(2, methodToolsCall, `"name":"write_file","arguments":{"region":"body"}`)
			rec.action = mcpTaskAction(opts, ParseMCPFrame([]byte(body)))
			f := &headerStateFixture{
				beforeList: func() {
					rec.rotated.Store(tc.name == "rotated")
					rec.expired.Store(tc.name == "expired")
				},
			}
			f.definitions.Store(strings.Replace(headerStateDefs(headerStateSchema, "Write a test file"), `"echo"`, strconv.Quote(tool), 1))
			upstream := httptest.NewServer(http.HandlerFunc(f.serveUpstream))
			t.Cleanup(upstream.Close)
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			headers := currentWireHeaders(methodToolsCall, tool)
			headers.Set("Proxy-Authorization", headerStateBearer)
			headers.Set("Mcp-Param-Region", "body")
			status, _, reply := postWireContractRequest(t, baseURL, body, headers)
			if status != http.StatusOK || f.lists.Load() != 1 || f.calls.Load() != tc.wantCalls || !strings.Contains(reply, tc.wantReply) ||
				(tc.wantCalls == 0 && !strings.Contains(reply, `"code":-32002`)) {
				t.Fatalf("status=%d discoveries=%d upstream calls=%d, want calls=%d and %q, response=%s",
					status, f.lists.Load(), f.calls.Load(), tc.wantCalls, tc.wantReply, reply)
			}
			if tc.wantCalls == 1 {
				records := observed.snapshot()
				if len(records) != 1 || records[0].Verdict != config.ActionAllow || records[0].DecisionPhase != "" {
					t.Fatalf("receipts = %+v, want one single-phase allow for the delivered call", records)
				}
			}
			if tc.wantCalls == 0 {
				// The refusal receipt must record the release-time taint
				// block, not the admission decision that allowed the call.
				refused := false
				for _, record := range observed.snapshot() {
					if record.Verdict == config.ActionBlock && record.TaintDecision == config.ActionBlock && record.TaintDecisionReason == tc.wantReply {
						refused = true
					}
				}
				if !refused {
					t.Fatalf("receipts = %+v, want a block recording taint reason %q", observed.snapshot(), tc.wantReply)
				}
			}
		})
	}
}

func TestTaskPermissionRefusesHostileCallsAcrossMCPTransports(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	msg := principalControlToolCall(1, "frobnicate_widget", `{"id":"1"}`)
	exposure := session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingToolPoisoning})
	stdioReceipts := &allReceipts{}
	stdioEmitter, _, _, _ := newReceiptTestHarnessWithObserver(t, stdioReceipts.observe)
	stdioRec := &listenerDiagnosisRecorder{}
	stdioRec.ObserveRisk(exposure)
	_, _ = runTaskPermissionMCPCall(t, "stdio", msg, MCPProxyOpts{
		Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Rec: stdioRec, ReceiptEmitter: stdioEmitter,
	})
	stdio := stdioReceipts.snapshot()
	if len(stdio) != 1 || stdio[0].TaintDecision != config.ActionBlock || stdio[0].TaintDecisionReason != "task_approval_unavailable" ||
		stdio[0].SessionTaintLevel != session.TaintExternalHostile.String() || stdio[0].AuthorityKind == "" {
		t.Fatalf("stdio reference receipts = %+v, want a hostile task approval refusal", stdio)
	}
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
					rec.ObserveRisk(exposure)
					opts := MCPProxyOpts{
						Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Approver: approver,
						Store: taskPermissionTestStore{rec: rec}, Rec: rec, ReceiptEmitter: emitter,
					}
					response, deliveries := runTaskPermissionMCPCall(t, mode, msg, opts)
					if !strings.Contains(response, tc.reason) || deliveries != 0 {
						t.Fatalf("upstream deliveries=%d response=%q, want zero deliveries and %q", deliveries, response, tc.reason)
					}
					records := observed.snapshot()
					if len(records) != 1 || records[0].Verdict != config.ActionBlock || records[0].Pattern != tc.reason {
						t.Fatalf("receipts = %+v, want one block with %q", records, tc.reason)
					}
					record, reference := records[0], stdio[0]
					if record.TaintDecision != reference.TaintDecision || record.TaintDecisionReason != tc.reason ||
						record.SessionTaintLevel != reference.SessionTaintLevel || record.AuthorityKind != reference.AuthorityKind ||
						record.SessionContaminated != reference.SessionContaminated || record.TaskOverrideApplied != reference.TaskOverrideApplied ||
						len(record.RecentTaintSources) != len(reference.RecentTaintSources) {
						t.Errorf("signed taint = %s/%s/%s/%s (contaminated=%t, override=%t), want %s/%s/%s/%s (contaminated=%t, override=%t)",
							record.TaintDecision, record.TaintDecisionReason, record.SessionTaintLevel, record.AuthorityKind,
							record.SessionContaminated, record.TaskOverrideApplied,
							reference.TaintDecision, tc.reason, reference.SessionTaintLevel, reference.AuthorityKind,
							reference.SessionContaminated, reference.TaskOverrideApplied)
					}
				})
			}
		})
	}
}

func runTaskPermissionMCPCall(t *testing.T, mode string, msg []byte, opts MCPProxyOpts, beforeWSUpgrade ...func()) (string, int) {
	t.Helper()
	if mode == "stdio" {
		opts.Transport = deferred.SurfaceMCPStdio
		var sent bytes.Buffer
		blocked := make(chan BlockedRequest, 1)
		ForwardScannedInput(transport.NewStdioReader(strings.NewReader(string(msg)+"\n")),
			transport.NewStdioWriter(&sent), io.Discard, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
		denial := <-blocked
		return denial.ErrorMessage, sent.Len()
	}

	var deliveries atomic.Int32
	wsReadDone := make(chan struct{})
	answer := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "websocket" {
			defer close(wsReadDone)
			for _, hook := range beforeWSUpgrade {
				hook()
			}
			conn, _, _, err := (ws.HTTPUpgrader{}).Upgrade(r, w)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			for {
				if _, _, err := gobwasutil.ReadClientData(conn); err != nil {
					return
				}
				deliveries.Add(1)
				if err := gobwasutil.WriteServerMessage(conn, ws.OpText, answer); err != nil {
					return
				}
			}
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
		err := runTaskPermissionWS(ctx, msg, func(input io.Reader) error {
			return RunWSProxy(ctx, input, &output, io.Discard, wsURL(upstream), opts)
		}, func() {
			testwait.For(t, 3*time.Second, func() bool { return output.contains(`"jsonrpc"`) }, "MCP WebSocket response")
		})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-wsReadDone:
		case <-ctx.Done():
			t.Fatal("upstream WebSocket reader did not finish")
		}
	default:
		t.Fatalf("unknown transport %q", mode)
	}
	return output.String(), int(deliveries.Load())
}

func runTaskPermissionWS(ctx context.Context, msg []byte, run func(io.Reader) error, waitForReply func()) error {
	r, w := io.Pipe()
	defer func() { _ = w.Close() }()
	// Bound the harness even when the proxy returns without reading.
	stop := context.AfterFunc(ctx, func() { _ = w.CloseWithError(ctx.Err()) })
	defer stop()
	done := make(chan error, 1)
	go func() {
		defer func() { _ = r.Close() }()
		done <- run(r)
	}()
	if _, err := io.WriteString(w, string(msg)+"\n"); err != nil {
		if proxyErr := <-done; proxyErr != nil {
			return proxyErr
		}
		return fmt.Errorf("writing WebSocket proxy input: %w", err)
	}
	waitForReply()
	_ = w.Close()
	return <-done
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
	prompt := &taskApprovalOutput{input: w, beforeAnswer: func() { rec.rotated.Store(true) }}
	approver := hitl.New(1, hitl.WithInput(r), hitl.WithOutput(prompt), hitl.WithTerminal(true))
	t.Cleanup(approver.Close)
	opts := MCPProxyOpts{
		Scanner: testScannerForHTTP(t), Rec: rec, TaintCfg: &cfg.Taint, Approver: approver,
		ServerBinding: "test-server", ServerRevision: "v1", TaskOperatorAPI: true, taskSubject: "verified-worker",
	}
	response, deliveries := runTaskPermissionMCPCall(t, "stdio", []byte(deferKillTestCall), opts)
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
			response, deliveries := runTaskPermissionMCPCall(t, tc.mode, msg, opts)
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
		bestEffort   bool
	}{
		{name: "request"},
		{name: "notification", notification: true},
		{name: "reply_write_error", writeFails: true},
		{name: "best_effort_request", bestEffort: true},
		{name: "best_effort_notification", notification: true, bestEffort: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, calls := countingUpstream(t)
			cfg := config.Defaults()
			rec := &httpTaskPermissionRecorder{expireAt: 3}
			rec.ObserveRisk(session.ClassifyMCPResponseFindings("mcp_response", true, []session.HostileFindingKind{session.FindingDLP}))
			emitter, _, dir, pubKey := newReceiptTestHarness(t)
			opts := MCPProxyOpts{
				Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint,
				Store: taskPermissionTestStore{rec: rec}, ServerBinding: "test-server", ReceiptEmitter: emitter, RequireReceipts: !tc.bestEffort,
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
			signed := readActionReceipts(t, dir)
			records := make([]receipt.ActionRecord, 0, len(signed))
			for _, record := range signed {
				if err := receipt.VerifyWithKey(record, pubKey); err != nil {
					t.Errorf("receipt signature: %v", err)
				}
				records = append(records, record.ActionRecord)
			}
			if len(records) != 2 || records[0].ActionID != records[1].ActionID ||
				records[0].DecisionPhase != receipt.DecisionPhaseIntent || records[0].Verdict != config.ActionAllow ||
				records[1].DecisionPhase != receipt.DecisionPhaseOutcome || records[1].Verdict != config.ActionBlock ||
				!strings.Contains(records[1].Pattern, "reason="+session.TaskPermissionRequired) || records[1].TaintDecision != config.ActionBlock || records[1].TaintDecisionReason != session.TaskPermissionRequired {
				for _, record := range records {
					t.Logf("receipt phase=%q verdict=%q pattern=%q", record.DecisionPhase, record.Verdict, record.Pattern)
				}
				t.Errorf("got %d receipts, want the intent closed by a task-permission block", len(records))
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
	response, deliveries := runTaskPermissionMCPCall(t, "stdio", msg, opts)
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
		if denial.ErrorCode != -32002 || !strings.HasPrefix(denial.ErrorMessage, "pipelock: "+session.TaskPermissionRequired+" (") {
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
