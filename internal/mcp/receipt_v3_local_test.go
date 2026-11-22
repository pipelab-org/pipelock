// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestMCPV3LocalHTTPBlock(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		required, fail, delivered bool
	}{
		{"required", true, false, true},
		{"optional", false, false, true},
		{"required writer failure", true, true, false},
		{"optional writer failure", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
			defer cancel()
			row := v3MCPMatrixRow{required: tc.required}
			if tc.fail && tc.required {
				row.scenario = "intent write fail"
			}
			opts, writer, client := localMCPReceiptFixture(t, row, "mcp_http_upstream")
			if tc.fail && !tc.required {
				if err := writer.Close(ctx, nil); err != nil {
					t.Fatal(err)
				}
			}
			opts.KillSwitch = deferKillTestController()
			opts.KillSwitch.SetAPI(true)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("blocked request reached upstream")
				w.WriteHeader(http.StatusBadRequest)
			}))
			defer upstream.Close()
			err := RunHTTPProxy(ctx, strings.NewReader(jsonToolsCallEcho+"\n"), client, io.Discard, upstream.URL, nil, opts)
			if err != nil {
				t.Fatal(err)
			}
			actions := localMCPReceiptActions(t, writer, client.dir)
			if !tc.delivered {
				if client.output.Len() != 0 {
					t.Fatalf("client observed withheld reply: %s", client.output.String())
				}
			} else {
				assertLocalMCPErrors(t, client.output.String(), "1")
			}
			if tc.fail {
				for _, a := range actions {
					if a.EffectBoundary == mcpDownstreamDeliveryBoundary && a.OutcomeClass == "completed" {
						t.Fatalf("unexpected completed delivery: %+v", a)
					}
				}
				return
			}
			if !client.intent {
				t.Fatal("no delivery intent before client write")
			}
			assertLocalMCPDeliveries(t, actions, "1")
		})
	}
}

func TestMCPV3LocalSendDenialDeliveryFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required bool
	}{
		{"required", true}, {"optional", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := v3MCPMatrixRow{required: tc.required, scenario: "send and local denial intent write fail"}
			opts, writer, client := localMCPReceiptFixture(t, row, "mcp_http_upstream")
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("request reached upstream")
				w.WriteHeader(http.StatusBadRequest)
			}))
			defer upstream.Close()
			if err := RunHTTPProxy(t.Context(), strings.NewReader(jsonToolsCallEcho+"\n"), client, io.Discard, upstream.URL, nil, opts); err != nil {
				t.Fatal(err)
			}
			if tc.required {
				if client.output.Len() != 0 {
					t.Fatalf("unrecorded denial reached client: %q", client.output.String())
				}
			} else {
				assertLocalMCPErrors(t, client.output.String(), "1")
			}
			for _, action := range localMCPReceiptActions(t, writer, client.dir) {
				if action.EffectBoundary == mcpDownstreamDeliveryBoundary && action.OutcomeClass == "completed" {
					t.Fatalf("unrecorded denial has a completed outcome: %+v", action)
				}
			}
		})
	}
}

func TestMCPV3LocalPresignedRefusal(t *testing.T) {
	opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, "mcp_http_upstream")
	opts.PolicyCfg = policy.New(config.MCPToolPolicy{
		Enabled: true, Action: config.ActionBlock,
		Rules: []config.ToolPolicyRule{{Name: "deny-echo", ToolPattern: "^echo$", Action: config.ActionBlock}},
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("blocked request reached upstream")
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer upstream.Close()
	err := RunHTTPProxy(t.Context(), strings.NewReader(jsonToolsCallEcho+"\n"), client, io.Discard, upstream.URL, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	assertLocalMCPErrors(t, client.output.String(), "1")
	actions := localMCPReceiptActions(t, writer, client.dir)
	if len(actions) != 1 || actions[0].EffectBoundary != mcpDownstreamDeliveryBoundary ||
		actions[0].Phase != "decision" || actions[0].Verdict != config.ActionBlock {
		t.Fatalf("expected only the pre-signed refusal, got %+v", actions)
	}
}

func TestMCPV3LocalTimeoutReplies(t *testing.T) {
	const input = jsonToolsCallEcho + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}` + "\n"
	for _, surface := range []string{transportMCPStdio, "mcp_http_upstream"} {
		for _, mode := range []struct {
			name     string
			required bool
		}{{"required", true}, {"optional", false}} {
			t.Run(surface+"/"+mode.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(8*time.Second))
				defer cancel()
				opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: mode.required}, surface)
				opts.InputCfg = &InputScanConfig{ResponseTimeoutSeconds: 1}
				var err error
				if surface == transportMCPStdio {
					in, feed := io.Pipe()
					defer func() { _ = in.Close(); _ = feed.Close() }()
					go func() { _, _ = io.WriteString(feed, input) }()
					cmd := []string{"sh", "-c", "read -r first && read -r second && read -r keep_open"}
					err = RunProxy(ctx, in, client, io.Discard, cmd, opts)
				} else {
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						w.(http.Flusher).Flush()
						<-r.Context().Done()
					}))
					defer upstream.Close()
					err = RunHTTPProxy(ctx, strings.NewReader(input), client, io.Discard, upstream.URL, nil, opts)
				}
				if !errors.Is(err, transport.ErrResponseTimeout) {
					t.Fatalf("expected response timeout, got %v", err)
				}
				assertLocalMCPErrors(t, client.output.String(), "1", "2")
				if !client.intent {
					t.Fatal("no delivery intent before client write")
				}
				assertLocalMCPDeliveries(t, localMCPReceiptActions(t, writer, client.dir), "1", "2")
			})
		}
	}
}

func TestMCPV3UnpairedReplyRemainsWithheld(t *testing.T) {
	for _, mode := range []struct {
		name     string
		required bool
	}{{"required", true}, {"optional", false}} {
		t.Run(mode.name, func(t *testing.T) {
			opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: mode.required}, transportMCPStdio)
			line := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
			_, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(string(line)+"\n")), transport.NewStdioWriter(client), io.Discard, NewStrictRequestTracker(), opts.withV3Session())
			if err != nil || client.output.Len() != 0 {
				t.Fatalf("unpaired response: output=%q error=%v", client.output.String(), err)
			}
			for _, a := range localMCPReceiptActions(t, writer, client.dir) {
				if a.EffectBoundary == mcpDownstreamDeliveryBoundary && a.OutcomeClass == "completed" {
					t.Fatalf("unpaired response recorded as delivered: %+v", a)
				}
			}
		})
	}
}

func localMCPReceiptFixture(t *testing.T, row v3MCPMatrixRow, surface string) (MCPProxyOpts, *v3.StreamWriter, *mcpMatrixObserver) {
	t.Helper()
	writerOpts := mcpMatrixWriterOptions(t, row, surface, nil, nil)
	writer, err := v3.OpenStreamWriter(t.Context(), writerOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close(context.Background(), nil) })
	opts := MCPProxyOpts{Scanner: testScannerWithAction(t, config.ActionBlock), Transport: surface}.WithV3ReceiptWriter(writer)
	return opts, writer, &mcpMatrixObserver{dir: writerOpts.Dir}
}

func localMCPReceiptActions(t *testing.T, writer *v3.StreamWriter, dir string) []v3.Action {
	t.Helper()
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	actions, err := readMCPMatrixActions(dir)
	if err != nil {
		t.Fatal(err)
	}
	return actions
}

func assertLocalMCPErrors(t *testing.T, output string, ids ...string) {
	t.Helper()
	seen := map[string]int{}
	for line := range strings.Lines(output) {
		if !strings.Contains(line, `"error":`) {
			t.Fatalf("expected JSON-RPC error, got %q", line)
		}
		seen[canonicalID(ParseMCPFrame([]byte(line)).ID)]++
	}
	if len(seen) != len(ids) {
		t.Fatalf("expected local errors for %v, got %q", ids, output)
	}
	for _, id := range ids {
		if seen[id] != 1 {
			t.Fatalf("expected one local error for %s, got %q", id, output)
		}
	}
}

func assertLocalMCPDeliveries(t *testing.T, actions []v3.Action, ids ...string) {
	t.Helper()
	sends := map[string]string{}
	intents := map[string]v3.Action{}
	outcomes := map[string]int{}
	for _, a := range actions {
		if a.EffectBoundary == mcpUpstreamSendBoundary && a.Phase == "intent" {
			sends[a.RequestID] = a.ActionID
		}
	}
	for _, a := range actions {
		switch {
		case a.EffectBoundary == mcpDownstreamDeliveryBoundary && a.Phase == "intent":
			if _, exists := intents[a.RequestID]; exists || a.ParentActionID != sends[a.RequestID] {
				t.Fatalf("duplicate or incorrectly linked intent: %+v", a)
			}
			intents[a.RequestID] = a
		case a.EffectBoundary == mcpDownstreamDeliveryBoundary && a.Phase == "outcome":
			if intents[a.RequestID].ActionID != a.ActionID || a.OutcomeClass != "completed" {
				t.Fatalf("unexpected delivery outcome: %+v", a)
			}
			outcomes[a.RequestID]++
		}
	}
	if len(intents) != len(ids) || len(outcomes) != len(ids) {
		t.Fatalf("expected one delivery per request %v, got %+v", ids, actions)
	}
	for _, id := range ids {
		if outcomes[id] != 1 {
			t.Fatalf("expected one completed delivery for %s, got %+v", id, actions)
		}
	}
}

func TestMCPV3DuplicateSendPreservesOriginalCorrelation(t *testing.T) {
	ctx := t.Context()
	opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, transportMCPStdio)
	opts = opts.withV3Session()
	frame := MCPFrame{ID: []byte("1"), Method: "tools/call", ToolCallName: "echo"}
	first, err := opts.startV3Send(ctx, frame, "first")
	if err != nil {
		t.Fatal(err)
	}
	if err := opts.bindV3Send(first); err != nil {
		t.Fatal(err)
	}
	second, err := opts.startV3Send(ctx, frame, "second")
	if err != nil {
		t.Fatal(err)
	}
	if err := opts.bindV3Send(second); err == nil {
		t.Fatal("duplicate request replaced the original send")
	}
	opts.finishV3Send(ctx, io.Discard, second, false)
	if got := opts.pendingV3Send(frame.ID); got != first {
		t.Fatal("duplicate settlement discarded the original send")
	}
	opts.settleV3Session(ctx, io.Discard)
	if err := opts.bindV3Send(first); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed session accepted a send: %v", err)
	}
	want := map[string]string{"first": "attempt_unknown", "second": "not_released"}
	for _, action := range localMCPReceiptActions(t, writer, client.dir) {
		if action.Phase == "outcome" && action.OutcomeClass == want[action.ActionID] {
			delete(want, action.ActionID)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing send settlements: %v", want)
	}
}

func TestMCPV3ServerInitiatedWebSocketDelivery(t *testing.T) {
	const surface = "mcp_ws"
	line := []byte(`{"jsonrpc":"2.0","id":17,"method":"ping"}`)
	opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, surface)
	opts = opts.withV3Session()
	frame := MCPFrame{ID: []byte("17"), Method: "ping"}
	base := transport.NewStdioWriter(client)
	stdioOpts := opts
	stdioOpts.Transport = deferred.SurfaceMCPStdio
	if stdioOpts.v3ResponseWriter(t.Context(), io.Discard, base, line, frame) != base {
		t.Fatal("WebSocket delivery gate changed the stdio server-request writer")
	}
	if err := opts.v3ResponseWriter(t.Context(), io.Discard, base, line, frame).WriteMessage(line); err != nil {
		t.Fatal(err)
	}
	if !client.intent || !strings.Contains(client.output.String(), string(line)) {
		t.Fatalf("request was not admitted and delivered: %q", client.output.String())
	}
	for _, action := range localMCPReceiptActions(t, writer, client.dir) {
		if action.RequestID == "17" && action.ParentActionID == "" &&
			action.EffectBoundary == mcpDownstreamDeliveryBoundary && action.OutcomeClass == "completed" {
			return
		}
	}
	t.Fatal("missing unparented server request delivery receipt")
}

func TestMCPV3NetworkReplyCancellationSettlesReservation(t *testing.T) {
	opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, "mcp_http_listener")
	opts = opts.withV3Session()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	x := mcpV3NetworkExchange{ctx: ctx, opts: opts, log: io.Discard}
	frame := MCPFrame{ID: []byte("1"), Method: "tools/list"}
	if err := x.admit(frame, "send"); err != nil {
		t.Fatal(err)
	}
	if err := x.admitReply(); err != nil {
		t.Fatal(err)
	}
	cancel()
	w := &mcpV3NetworkStreamWriter{exchange: &x, base: transport.NewStdioWriter(client)}
	if err := w.WriteMessage([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write returned %v", err)
	}
	if err := w.writeDeniedMessage(nil); err != nil {
		t.Fatal(err)
	}
	x.finish()
	if client.output.Len() != 0 {
		t.Fatalf("cancelled reply reached client: %q", client.output.String())
	}
	want := map[string]bool{mcpDownstreamDeliveryBoundary: true, mcpUpstreamSendBoundary: true}
	for _, action := range localMCPReceiptActions(t, writer, client.dir) {
		if action.OutcomeClass == "not_released" {
			delete(want, action.EffectBoundary)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing unattempted settlements: %v", want)
	}
}

func TestMCPV3ListenerLegacyMethodReceipts(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		for _, scenario := range []string{"success", "intent write fail"} {
			t.Run(method+"/"+scenario, func(t *testing.T) {
				surface := "mcp_http_listener"
				opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true, scenario: scenario}, surface)
				calls := make(chan string, 1)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					select {
					case calls <- r.Method:
					default:
						t.Error("duplicate upstream request")
					}
					if r.Method == http.MethodGet {
						w.Header().Set("Content-Type", "text/event-stream")
						return
					}
					w.WriteHeader(http.StatusAccepted)
				}))
				defer upstream.Close()
				baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
				req, err := http.NewRequestWithContext(t.Context(), method, baseURL, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Accept", "text/event-stream")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				if _, err := io.Copy(io.Discard, resp.Body); err != nil {
					t.Fatal(err)
				}
				actions := localMCPReceiptActions(t, writer, client.dir)
				if scenario == "intent write fail" {
					if resp.StatusCode != http.StatusServiceUnavailable || len(calls) != 0 {
						t.Fatalf("failed admission: status=%d upstream calls=%d", resp.StatusCode, len(calls))
					}
					return
				}
				wantStatus, outcome := http.StatusOK, "attempt_unknown"
				if method == http.MethodDelete {
					wantStatus, outcome = http.StatusAccepted, "completed"
				}
				if resp.StatusCode != wantStatus || len(calls) != 1 || <-calls != method {
					t.Fatalf("unexpected %s response: status=%d", method, resp.StatusCode)
				}
				var send, reply v3.Action
				for _, action := range actions {
					if action.Phase != "outcome" {
						continue
					}
					switch action.EffectBoundary {
					case mcpUpstreamSendBoundary:
						send = action
					case mcpDownstreamDeliveryBoundary:
						reply = action
					}
				}
				if send.ActionID == "" || send.OutcomeClass != "completed" ||
					reply.ParentActionID != send.ActionID || reply.OutcomeClass != outcome {
					t.Fatalf("unexpected send and reply settlements: send=%+v reply=%+v", send, reply)
				}
			})
		}
	}
}

func TestMCPV3ApprovalStepUpRetainsChannel(t *testing.T) {
	for _, source := range []string{deferred.SourceApproval, deferred.SourceOperator} {
		t.Run(source, func(t *testing.T) {
			opts, writerOpts := openMCPV3RegressionWriter(t, transportMCPStdio)
			proxy := MCPProxyOpts{Transport: transportMCPStdio}.WithV3ReceiptWriter(opts).withV3Session()
			manager := deferred.NewManager(deferred.Config{Enabled: true})
			var delivered deferred.Resolution
			held := deferred.HeldAction{
				DeferID: "hold", ActionID: "action", Method: "tools/call", Target: "echo",
				RulePolicy: config.DeferResolutionPolicy{
					StepUpOn: config.DeferStepUpOn{ApprovalRequestsHuman: true},
				},
				Resolve: func(res deferred.Resolution) { delivered = res },
			}
			proxy.confirmV3Hold(&held, MCPFrame{ID: []byte("1"), Method: held.Method})
			if err := manager.HoldContext(t.Context(), held); err != nil {
				t.Fatal(err)
			}
			if source == deferred.SourceOperator {
				if err := manager.ResolveContext(t.Context(), held.DeferID, config.ActionStepUp, source); err != nil {
					t.Fatal(err)
				}
				if delivered.FinalDecision != config.ActionStepUp {
					t.Fatalf("raw step-up delivered=%q", delivered.FinalDecision)
				}
			} else {
				applied, err := manager.ResolveApprovalResult(held.DeferID, config.ActionStepUp, source)
				if err != nil || applied != config.ActionAsk || delivered.FinalDecision != config.ActionAsk {
					t.Fatalf("step-up applied=%q delivered=%q error=%v", applied, delivered.FinalDecision, err)
				}
			}
			actions := verifiedMCPV3RegressionActions(t, opts, writerOpts)
			if len(actions) != 2 || actions[1].ActionID != held.ActionID || actions[1].Hold == nil ||
				actions[1].Hold.ID != held.DeferID || actions[1].Hold.ResolutionSource != source ||
				actions[1].Verdict != config.ActionAsk || actions[1].Ask == nil ||
				actions[1].Ask.Channel != "approval_api" || !actions[1].Ask.Observed {
				t.Fatalf("missing observed approval channel: %+v", actions)
			}
		})
	}
}

func TestMCPV3ListenerInventoryAdmissionFailure(t *testing.T) {
	for _, scenario := range []string{"intent write fail", "preadmitted reply intent write fail"} {
		t.Run(scenario, func(t *testing.T) {
			row := v3MCPMatrixRow{required: true, scenario: scenario}
			opts, writer, client := localMCPReceiptFixture(t, row, deferred.SurfaceMCPHTTPListener)
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("inventory request reached upstream without both receipts")
			}))
			defer upstream.Close()
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL,
				strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), "receipt admission failed") &&
				!strings.Contains(string(body), "receipt emission failed") {
				t.Fatalf("admission failure: status=%d body=%q", resp.StatusCode, body)
			}
			for _, action := range localMCPReceiptActions(t, writer, client.dir) {
				if action.EffectBoundary == mcpUpstreamSendBoundary && action.OutcomeClass == "completed" {
					t.Fatalf("withheld inventory recorded as sent: %+v", action)
				}
			}
		})
	}
}

func TestMCPV3ListenerReplyAdmissionFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body        string
		contentType string
		wantStatus  int
	}{
		{"json", http.StatusOK, `{"jsonrpc":"2.0","id":1,"result":{"value":"withheld reply"}}`, "application/json", http.StatusServiceUnavailable},
		{"acknowledgment", http.StatusAccepted, "", "application/json", http.StatusServiceUnavailable},
		{"client error", http.StatusTooManyRequests, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"withheld reply"}}`, "application/json", http.StatusServiceUnavailable},
		{"sse", http.StatusOK, "event: message\ndata: " + `{"jsonrpc":"2.0","id":1,"result":{"value":"withheld reply"}}` + "\n\n", "text/event-stream", http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := v3MCPMatrixRow{required: true, scenario: "preadmitted reply intent write fail"}
			opts, writer, client := localMCPReceiptFixture(t, row, deferred.SurfaceMCPHTTPListener)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("Mcp-Session-Id", "example-session")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer upstream.Close()
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL, strings.NewReader(jsonToolsCallEcho))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.wantStatus || resp.Header.Get("Mcp-Session-Id") != "" ||
				strings.Contains(string(body), "withheld reply") {
				t.Fatalf("unrecorded reply escaped: status=%d headers=%v body=%q", resp.StatusCode, resp.Header, body)
			}
			for _, action := range localMCPReceiptActions(t, writer, client.dir) {
				if action.EffectBoundary == mcpDownstreamDeliveryBoundary && action.OutcomeClass == "completed" {
					t.Fatalf("withheld reply recorded as completed: %+v", action)
				}
			}
		})
	}
}

func TestMCPV3DeferredStdioWriteFailureSettlesSend(t *testing.T) {
	opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, deferred.SurfaceMCPStdio)
	opts = opts.withV3Session()
	opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true})
	policyCfg := deferApprovalPolicy(config.DeferResolverProfile{})
	policyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
	opts.PolicyCfg = policyCfg
	tracker := NewRequestTracker()
	blocked := make(chan BlockedRequest, 1)
	input, feed := io.Pipe()
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = feed.Close()
		select {
		case <-done:
		case <-time.After(testwait.Deadline(5 * time.Second)):
			t.Error("stdio input loop did not stop")
		}
	})
	go func() {
		defer close(done)
		ForwardScannedInput(transport.NewStdioReader(input), deferredReleaseFailWriter{}, io.Discard,
			config.ActionWarn, config.ActionBlock, blocked, nil, tracker, opts)
	}()
	if _, err := io.WriteString(feed, deferKillTestCall); err != nil {
		t.Fatal(err)
	}
	testwait.For(t, time.Second, func() bool { return opts.DeferManager.HeldCount() == 1 }, "confirmed hold")
	hold := opts.DeferManager.Snapshot()[0]
	if err := opts.DeferManager.Resolve(hold.DeferID, config.ActionAllow, deferred.SourceApproval); err != nil {
		t.Fatal(err)
	}
	select {
	case denial := <-blocked:
		if denial.ErrorCode == 0 {
			t.Fatalf("missing terminal error: %+v", denial)
		}
	default:
		t.Fatal("failed send did not produce a terminal error")
	}
	if tracker.HasPending() {
		t.Fatal("failed write left a pending response")
	}
	for _, action := range localMCPReceiptActions(t, writer, client.dir) {
		if action.ActionID == hold.ActionID && action.EffectBoundary == mcpUpstreamSendBoundary &&
			action.OutcomeClass == "attempt_unknown" {
			return
		}
	}
	t.Fatal("missing unknown settlement after the failed send")
}

func TestMCPV3ListenerGETWithholdsUnrecordedEvent(t *testing.T) {
	row := v3MCPMatrixRow{required: true, scenario: "reply intent write fail"}
	opts, writer, client := localMCPReceiptFixture(t, row, deferred.SurfaceMCPHTTPListener)
	const event = `{"jsonrpc":"2.0","method":"notifications/resources/list_changed"}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected upstream method %s", r.Method)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Mcp-Session-Id", "example-session")
		_, _ = io.WriteString(w, "event: message\ndata: "+event+"\n\n")
	}))
	defer upstream.Close()
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("Mcp-Session-Id") != "" || strings.Contains(string(body), event) {
		t.Fatalf("unrecorded event escaped: status=%d headers=%v body=%q", resp.StatusCode, resp.Header, body)
	}
	for _, action := range localMCPReceiptActions(t, writer, client.dir) {
		if action.EffectBoundary == mcpDownstreamDeliveryBoundary && action.OutcomeClass == "completed" {
			t.Fatalf("withheld event recorded as complete: %+v", action)
		}
	}
}

func TestMCPV3DisabledAdapterLeavesExistingWritersInPlace(t *testing.T) {
	ctx := t.Context()
	opts := (MCPProxyOpts{}).WithV3ReceiptWriter(nil).withV3Session()
	evidence := receipt.EmitOpts{ActionID: "action", Verdict: config.ActionAllow}
	token, err := opts.admitV3Effect(ctx, evidence, mcpUpstreamSendBoundary)
	if token != nil || err != nil {
		t.Fatalf("disabled admission: token=%v error=%v", token, err)
	}
	if err := opts.refuseV3Reply(ctx, evidence); err != nil {
		t.Fatal(err)
	}
	var held deferred.HeldAction
	opts.confirmV3Hold(&held, MCPFrame{})
	if held.ConfirmHold != nil || held.ConfirmResolution != nil {
		t.Fatal("disabled adapter installed approval callbacks")
	}
	base := transport.NewStdioWriter(io.Discard)
	exchange := mcpV3NetworkExchange{ctx: ctx, opts: opts, log: io.Discard}
	if exchange.streamWriter(base) != base {
		t.Fatal("disabled exchange replaced the stream writer")
	}
}

func TestMCPV3ReplyRetainsDecisionTimePolicy(t *testing.T) {
	opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, deferred.SurfaceMCPWS)
	digest := v3.Digest([]byte("policy"))
	request := receipt.EmitOpts{RequestID: "1", PolicyHash: strings.TrimPrefix(digest, "sha256:"), Transport: opts.Transport}
	reply := mcpV3ReplyWriter{base: transport.NewStdioWriter(client), opts: opts, log: io.Discard, request: request}
	msg := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	for range 2 {
		if err := reply.WriteMessage(msg); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Count(client.output.String(), string(msg)) != 1 {
		t.Fatalf("duplicate reply escaped: %q", client.output.String())
	}
	actions := localMCPReceiptActions(t, writer, client.dir)
	if len(actions) != 2 || actions[0].Policy.Hash != digest || actions[1].Policy.Hash != digest {
		t.Fatalf("reply lost decision-time policy: %+v", actions)
	}
	var output bytes.Buffer
	logMCPV3Error(&output, context.DeadlineExceeded)
	if !strings.Contains(output.String(), "audit_gap=true") {
		t.Fatalf("receipt deadline did not report an audit gap: %q", output.String())
	}
}

type cancelOnLock struct {
	sync.Mutex
	cancel context.CancelFunc
}

func (l *cancelOnLock) Lock() {
	l.Mutex.Lock()
	l.cancel()
}

func TestMCPV3CancelledDeferredClaimReleasesLock(t *testing.T) {
	opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, deferred.SurfaceMCPStdio)
	opts = opts.withV3Session()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	lock := &cancelOnLock{cancel: cancel}
	frame := MCPFrame{ID: []byte("1"), Method: "tools/call"}
	res := deferred.Resolution{ParentActionID: "send", FinalDecision: config.ActionAllow}
	send, finish, reason, err := opts.claimV3DeferredSend(ctx, io.Discard, frame, res, lock, 0)
	if send != nil || finish != nil || reason == "" || err != nil {
		t.Fatalf("cancelled claim: send=%v reason=%q error=%v", send, reason, err)
	}
	if !lock.TryLock() {
		t.Fatal("cancelled claim retained the transport lock")
	}
	lock.Unlock()
	for _, action := range localMCPReceiptActions(t, writer, client.dir) {
		if action.ActionID == res.ParentActionID && action.OutcomeClass == "not_released" {
			return
		}
	}
	t.Fatal("cancelled claim did not settle its send")
}

func TestMCPV3NetworkReplyRefusalIsSigned(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "buffered", true: "streamed"}[stream], func(t *testing.T) {
			opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, deferred.SurfaceMCPHTTPListener)
			x := mcpV3NetworkExchange{ctx: t.Context(), opts: opts, log: io.Discard}
			frame := MCPFrame{ID: []byte("1"), Method: "tools/call"}
			if err := x.admit(frame, "send"); err != nil {
				t.Fatal(err)
			}
			x.sent = true
			x.observe()
			if stream {
				w := mcpV3NetworkStreamWriter{exchange: &x, base: transport.NewStdioWriter(client)}
				if err := w.writeDeniedMessage(nil); err != nil {
					t.Fatal(err)
				}
			} else {
				x.refuseReply()
			}
			x.finish()
			if client.output.Len() != 0 {
				t.Fatalf("withheld reply reached the client: %q", client.output.String())
			}
			for _, action := range localMCPReceiptActions(t, writer, client.dir) {
				if action.EffectBoundary == mcpDownstreamDeliveryBoundary && action.ParentActionID == "send" &&
					action.Phase == "decision" && action.Verdict == config.ActionBlock {
					return
				}
			}
			t.Fatal("missing signed reply refusal")
		})
	}
}

type brokenListenerBody struct {
	*httptest.ResponseRecorder
}

func (brokenListenerBody) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestMCPV3ListenerDenialWriteErrorPreventsFlush(t *testing.T) {
	rec := httptest.NewRecorder()
	descriptor := mcpDenialAudit{}
	w := mcpListenerDenialWriter{ResponseWriter: brokenListenerBody{rec}, descriptor: &descriptor}
	if err := w.WriteMessage([]byte("{}")); !errors.Is(err, io.ErrClosedPipe) || rec.Flushed {
		t.Fatalf("denial write failed: error=%v flushed=%t", err, rec.Flushed)
	}
}

type shortReplyWriter struct{}

func (shortReplyWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestMCPV3StdioWriterRejectsPartialReply(t *testing.T) {
	w := syncWriter{w: shortReplyWriter{}, requireFullMessage: true}
	if err := w.WriteMessage([]byte("{}")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("partial reply returned %v", err)
	}
}

func TestMCPV3ListenerAdmissionFailureKeepsNotificationResponseEmpty(t *testing.T) {
	row := v3MCPMatrixRow{required: true, scenario: "intent write fail"}
	opts, writer, client := localMCPReceiptFixture(t, row, deferred.SurfaceMCPHTTPListener)
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unadmitted notification reached upstream")
	}))
	defer upstream.Close()
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL,
		strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusAccepted || len(body) != 0 {
		t.Fatalf("notification response: status=%d body=%q error=%v", resp.StatusCode, body, err)
	}
	for _, action := range localMCPReceiptActions(t, writer, client.dir) {
		if action.OutcomeClass == "completed" {
			t.Fatalf("failed notification recorded as completed: %+v", action)
		}
	}
}

func TestMCPV3StdioCorrelationRefusalRemovesLegacyTracking(t *testing.T) {
	ctx := t.Context()
	opts, writer, client := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, deferred.SurfaceMCPStdio)
	opts = opts.withV3Session()
	first, err := opts.startV3Send(ctx, ParseMCPFrame([]byte(jsonToolsCallEcho)), "first")
	if err != nil {
		t.Fatal(err)
	}
	if err := opts.bindV3Send(first); err != nil {
		t.Fatal(err)
	}
	tracker := NewRequestTracker()
	blocked := make(chan BlockedRequest, 1)
	var upstream bytes.Buffer
	ForwardScannedInput(transport.NewStdioReader(strings.NewReader(jsonToolsCallEcho+"\n")),
		transport.NewStdioWriter(&upstream), io.Discard, config.ActionWarn, config.ActionBlock,
		blocked, nil, tracker, opts)
	if upstream.Len() != 0 || tracker.HasPending() || len(blocked) != 1 {
		t.Fatalf("correlation refusal: upstream=%q pending=%t denials=%d", upstream.String(), tracker.HasPending(), len(blocked))
	}
	opts.settleV3Session(ctx, io.Discard)
	for _, action := range localMCPReceiptActions(t, writer, client.dir) {
		if action.ActionID != first.request.ActionID && action.EffectBoundary == mcpUpstreamSendBoundary &&
			action.OutcomeClass == "not_released" {
			return
		}
	}
	t.Fatal("duplicate send was not settled as unattempted")
}
