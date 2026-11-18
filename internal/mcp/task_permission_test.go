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

func TestStdioTaskPermissionRefusesUndeclaredToolsAfterHostileExposure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		tool         string
		args         string
		finding      session.HostileFindingKind
		wantDelivery int
	}{
		{"delegation", "delegate_task", `{"task":"summarize","recipient":"other-agent"}`, session.FindingDLP, 0},
		{"unknown", "frobnicate_widget", `{"id":"1"}`, session.FindingToolPoisoning, 0},
		{"read_name", "get_status", `{"path":"/workspace/status.txt"}`, session.FindingDLP, 0},
		{"clean_write", "write_file", `{"path":"/workspace/status.txt","content":"ready"}`, "", 1},
		{"wording_only", "delegate_task", `{"task":"summarize"}`, session.FindingWording, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Taint.FailSafeClassification = false
			rec := &taintRecorder{}
			opts := MCPProxyOpts{Scanner: testScannerWithAction(t, config.ActionWarn), Rec: rec, TaintCfg: &cfg.Taint, TaintExternalSource: true}
			if tc.finding != "" {
				observeMCPResponseFindings(opts, []session.HostileFindingKind{tc.finding})
			}
			msg := principalControlToolCall(1, tc.tool, tc.args)
			var sent bytes.Buffer
			blocked := make(chan BlockedRequest, 1)
			ForwardScannedInput(transport.NewStdioReader(strings.NewReader(string(msg)+"\n")), transport.NewStdioWriter(&sent), io.Discard,
				config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
			if count := bytes.Count(sent.Bytes(), []byte("\n")); count != tc.wantDelivery {
				t.Errorf("upstream deliveries = %d, want %d", count, tc.wantDelivery)
			}
			denial, refused := <-blocked
			if tc.wantDelivery == 0 && (!refused || !strings.Contains(denial.ErrorMessage, "task_approval_unavailable")) {
				t.Errorf("denial = %q, want task_approval_unavailable", denial.ErrorMessage)
			}
			if tc.wantDelivery > 0 && refused {
				t.Errorf("unexpected denial: %s", denial.ErrorMessage)
			}
		})
	}
}

type taskPermissionTestStore struct{ rec session.Recorder }

func (s taskPermissionTestStore) GetOrCreate(string) session.Recorder { return s.rec }
func (taskPermissionTestStore) Delete(string)                         {}

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
			msg := principalControlToolCall(1, "get_status", `{"path":"/workspace/summary.txt"}`)
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
