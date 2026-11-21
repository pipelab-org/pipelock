// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
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
			assertLocalMCPDeliveries(t, actions, false, "1")
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
				assertLocalMCPDeliveries(t, localMCPReceiptActions(t, writer, client.dir), true, "1", "2")
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

func assertLocalMCPDeliveries(t *testing.T, actions []v3.Action, parented bool, ids ...string) {
	t.Helper()
	sends := map[string]string{}
	intents := map[string]v3.Action{}
	outcomes := map[string]int{}
	for _, a := range actions {
		switch {
		case a.EffectBoundary == mcpUpstreamSendBoundary && a.Phase == "intent":
			sends[a.RequestID] = a.ActionID
		case a.EffectBoundary == mcpDownstreamDeliveryBoundary && a.Phase == "intent":
			if _, exists := intents[a.RequestID]; exists || a.ParentActionID != sends[a.RequestID] || (a.ParentActionID != "") != parented {
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
