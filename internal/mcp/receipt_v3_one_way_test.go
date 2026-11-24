// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const clientRPCReply = `{"jsonrpc":"2.0","id":1,"result":{}}`

func TestMCPV3ClientReplyLeavesRequestIDAvailable(t *testing.T) {
	for _, tc := range []struct{ name, surface string }{
		{"subprocess", transportMCPStdio},
		{"sandbox", transportMCPStdio},
		{"HTTP bridge", deferred.SurfaceMCPHTTPUpstream},
		{"HTTP listener", deferred.SurfaceMCPHTTPListener},
		{"WebSocket", deferred.SurfaceMCPWS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, writer, observer := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, tc.surface)
			input := clientRPCReply + "\n" + jsonToolsCallEcho + "\n"
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(4*time.Second))
			defer cancel()
			var upstream lockedHTTPBuffer
			if tc.surface == transportMCPStdio {
				path := filepath.Join(t.TempDir(), "upstream")
				cmd := []string{"sh", "-c", `cat > "$1"`, "fixture", path}
				in := strings.NewReader(input)
				var err error
				if tc.name == "sandbox" {
					child := exec.CommandContext(ctx, "sh", "-c", "cat > upstream")
					child.Dir = filepath.Dir(path)
					err = runProxyWithSandbox(ctx, child, child.Start, in, io.Discard, io.Discard, opts)
				} else {
					err = RunProxy(ctx, in, io.Discard, io.Discard, cmd, opts)
				}
				if err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(filepath.Clean(path))
				if err != nil {
					t.Fatal(err)
				}
				_, _ = upstream.Write(data)
			} else {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if tc.surface == deferred.SurfaceMCPWS {
						conn, _, _, err := ws.UpgradeHTTP(r, w)
						if err != nil {
							t.Error(err)
							return
						}
						defer func() { _ = conn.Close() }()
						for range 2 {
							body, _, err := wsutil.ReadClientData(conn)
							if err != nil {
								return
							}
							_, _ = upstream.Write(append(body, '\n'))
						}
						return
					}
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					_, _ = upstream.Write(append(body, '\n'))
					w.WriteHeader(http.StatusAccepted)
				}))
				defer server.Close()
				switch tc.surface {
				case deferred.SurfaceMCPWS:
					rd, wr := io.Pipe()
					defer func() { _ = rd.Close(); _ = wr.Close() }()
					go func() { _, _ = io.WriteString(wr, input) }()
					if err := RunWSProxy(ctx, rd, io.Discard, io.Discard, wsURL(server), opts); err != nil {
						t.Fatal(err)
					}
				case deferred.SurfaceMCPHTTPListener:
					base, _ := startListenerProxyWithOpts(t, server.URL, opts)
					for _, message := range []string{clientRPCReply, jsonToolsCallEcho} {
						req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, strings.NewReader(message))
						if err != nil {
							t.Fatal(err)
						}
						req.Header.Set("Content-Type", "application/json")
						resp, err := http.DefaultClient.Do(req)
						if err != nil {
							t.Fatal(err)
						}
						_, readErr := io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
						if readErr != nil || resp.StatusCode != http.StatusAccepted {
							t.Fatalf("POST status=%d error=%v", resp.StatusCode, readErr)
						}
					}
				default:
					if err := RunHTTPProxy(ctx, strings.NewReader(input), io.Discard, io.Discard, server.URL, nil, opts); err != nil {
						t.Fatal(err)
					}
				}
			}
			if upstream.String() != input {
				t.Errorf("upstream received %q, want both messages", upstream.String())
			}
			var outcomes []string
			for _, action := range localMCPReceiptActions(t, writer, observer.dir) {
				if action.EffectBoundary == mcpUpstreamSendBoundary && action.Method == "" && action.Phase == "outcome" {
					outcomes = append(outcomes, action.OutcomeClass)
				}
			}
			if !slices.Equal(outcomes, []string{"completed"}) {
				t.Errorf("one-way send outcomes = %v", outcomes)
			}
		})
	}
}

type partialReplyFixture struct{ out *strings.Builder }

func (w partialReplyFixture) Write(p []byte) (int, error) {
	return w.out.Write(p[:len(p)/2])
}

func TestMCPV3ClientReplyShortWriteRemainsUnknown(t *testing.T) {
	var prefix strings.Builder
	opts, writer, observer := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, transportMCPStdio)
	opts = opts.withV3Session()
	ForwardScannedInput(transport.NewStdioReader(strings.NewReader(clientRPCReply+"\n")),
		transport.NewStdioWriter(partialReplyFixture{out: &prefix}), io.Discard, config.ActionWarn, config.ActionBlock,
		make(chan BlockedRequest, 1), nil, NewRequestTracker(), opts)
	var outcomes []string
	for _, action := range localMCPReceiptActions(t, writer, observer.dir) {
		if action.Phase == "outcome" {
			outcomes = append(outcomes, action.OutcomeClass)
		}
	}
	if !slices.Equal(outcomes, []string{"attempt_unknown"}) {
		t.Fatalf("partial send outcomes = %v", outcomes)
	}
	if prefix.Len() == 0 || prefix.Len() >= len(clientRPCReply) || !strings.HasPrefix(clientRPCReply, prefix.String()) {
		t.Fatalf("partial write sent %q", prefix.String())
	}
}

func TestMCPV3ClientReplyHTTPDialFailureRemainsUnknown(t *testing.T) {
	opts, writer, observer := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, deferred.SurfaceMCPHTTPUpstream)
	opts.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("fixture dial failure")
	}
	if err := RunHTTPProxy(t.Context(), strings.NewReader(clientRPCReply+"\n"), io.Discard, io.Discard,
		"http://upstream.example", nil, opts); err != nil {
		t.Fatal(err)
	}
	actions := localMCPReceiptActions(t, writer, observer.dir)
	if len(actions) != 2 || actions[1].OutcomeClass != "attempt_unknown" {
		t.Fatalf("unconfirmed HTTP send receipts = %+v", actions)
	}
}

type partialHTTPWriteConn struct {
	net.Conn
	prefix *atomic.Int64
}

func (c partialHTTPWriteConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p[:len(p)/2])
	c.prefix.Add(int64(n))
	if err != nil {
		return n, err
	}
	return n, io.ErrShortWrite
}

func TestMCPV3ClientReplyHTTPPartialWriteRemainsUnknown(t *testing.T) {
	opts, writer, observer := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, deferred.SurfaceMCPHTTPUpstream)
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("partial write produced a full request")
	}))
	defer upstream.Close()
	var prefix atomic.Int64
	opts.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return partialHTTPWriteConn{Conn: conn, prefix: &prefix}, nil
	}
	if err := RunHTTPProxy(t.Context(), strings.NewReader(clientRPCReply+"\n"), io.Discard, io.Discard,
		upstream.URL, nil, opts); err != nil {
		t.Fatal(err)
	}
	actions := localMCPReceiptActions(t, writer, observer.dir)
	if len(actions) != 2 || actions[1].OutcomeClass != "attempt_unknown" {
		t.Fatalf("partial HTTP send receipts = %+v", actions)
	}
	if prefix.Load() == 0 {
		t.Fatal("partial HTTP write sent no bytes")
	}
}

func TestValidateMCPClientReply(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		accepted   bool
	}{
		{"result", clientRPCReply, true},
		{"error", `{"jsonrpc":"2.0","id":"request","error":{"code":-32000,"message":"denied"}}`, true},
		{"mixed envelope", `{"jsonrpc":"2.0","id":1,"method":"tools/list","result":{}}`, false},
		{"mixed disposition", `{"jsonrpc":"2.0","id":1,"result":{},"error":{}}`, false},
		{"missing ID", `{"jsonrpc":"2.0","result":{}}`, false},
		{"object ID", `{"jsonrpc":"2.0","id":{},"result":{}}`, false},
		{"invalid error", `{"jsonrpc":"2.0","id":1,"error":{"code":1}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reason := validateMCPClientReply([]byte(tc.body)); (reason == "") != tc.accepted {
				t.Fatalf("accepted=%t, reason=%q", tc.accepted, reason)
			}
		})
	}
}

func TestMCPV3CurrentProtocolDiscoveryAndClientReply(t *testing.T) {
	for _, listener := range []bool{false, true} {
		name, surface := "bridge", deferred.SurfaceMCPHTTPUpstream
		if listener {
			name, surface = "listener", deferred.SurfaceMCPHTTPListener
		}
		t.Run(name, func(t *testing.T) {
			writer, writerOpts := openMCPV3RegressionWriter(t, surface)
			opts := paramContractOpts(t).WithV3ReceiptWriter(writer)
			opts.Transport = surface
			seen := make(chan string, 4)
			wire := make(chan mcpWireObservation, 4)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				frame := ParseMCPFrame(body)
				if r.Header.Get(listenerProtocolVersion) != currentMCPVersion {
					t.Errorf("protocol header = %q", r.Header.Get(listenerProtocolVersion))
				}
				before, err := decodeMCPMatrixReceiptFiles(writerOpts.Dir, true)
				if err != nil {
					t.Error(err)
				}
				select {
				case wire <- mcpWireObservation{message: body, before: before, requestID: canonicalID(frame.ID), boundary: mcpUpstreamSendBoundary, outcome: "completed"}:
				default:
					t.Error("unexpected extra upstream observation")
				}
				select {
				case seen <- frame.Method:
				default:
					t.Error("unexpected extra upstream request")
				}
				switch frame.Method {
				case "initialize":
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprintf(w, "{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"protocolVersion\":%q}}", currentMCPVersion)
				case "tools/list":
					w.Header().Set("Content-Type", "application/json")
					discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
				case methodToolsCall:
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}")
				default:
					w.WriteHeader(http.StatusAccepted)
				}
			}))
			defer server.Close()
			body := currentWireBody(2, methodToolsCall, "\"name\":\"echo\",\"arguments\":{\"region\":\"body\"}")
			if listener {
				url, _ := startListenerProxyWithOpts(t, server.URL, opts)
				headers := currentWireHeaders(methodToolsCall, "echo")
				headers.Set("Mcp-Param-Region", "body")
				headers.Set("Proxy-Authorization", headerStateBearer)
				headers.Set("Authorization", "Bearer upstream-first")
				if status, _, msg := postWireContractRequest(t, url, body, headers); status != http.StatusOK {
					t.Fatalf("tools/call status = %d, body = %s", status, msg)
				}
				headers = currentWireHeaders("", "")
				headers.Del(listenerMCPMethod)
				headers.Set("Proxy-Authorization", headerStateBearer)
				headers.Set("Authorization", "Bearer upstream-first")
				if status, _, msg := postWireContractRequest(t, url, clientRPCReply, headers); status != http.StatusAccepted {
					t.Fatalf("client reply status = %d, body = %s", status, msg)
				}
			} else {
				var out strings.Builder
				input := strings.NewReader(currentWireBody(0, "initialize", "") + "\n" + body + "\n" + clientRPCReply + "\n")
				if err := RunHTTPProxy(t.Context(), input, &out, io.Discard, server.URL, nil, opts); err != nil {
					t.Fatal(err)
				}
				if got := strings.TrimSpace(out.String()); !strings.HasSuffix(got, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}") || strings.Count(got, "\n") != 1 {
					t.Fatalf("client received %s", got)
				}
			}
			close(seen)
			var methods []string
			for method := range seen {
				methods = append(methods, method)
			}
			wantMethods := []string{"tools/list", methodToolsCall, ""}
			if !listener {
				wantMethods = append([]string{"initialize"}, wantMethods...)
			}
			if !slices.Equal(methods, wantMethods) {
				t.Fatalf("upstream methods = %v", methods)
			}
			close(wire)
			var observed []mcpWireObservation
			for message := range wire {
				observed = append(observed, message)
			}
			actions := verifiedMCPV3RegressionActions(t, writer, writerOpts)
			if err := checkMCPWireObservations(actions, mcpUpstreamSendBoundary, observed); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMCPV3RejectedResponseDoesNotClaimValidReply(t *testing.T) {
	const invalid = "{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":1,\"result\":{}}"
	for _, name := range []string{"stdio", "sandbox", "WebSocket", "HTTP bridge"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(4*time.Second))
			defer cancel()
			surface := transportMCPStdio
			switch name {
			case "WebSocket":
				surface = deferred.SurfaceMCPWS
			case "HTTP bridge":
				surface = deferred.SurfaceMCPHTTPUpstream
			}
			writer, writerOpts := openMCPV3RegressionWriter(t, surface)
			opts := (MCPProxyOpts{Transport: surface, Scanner: testScannerWithAction(t, config.ActionBlock)}).WithV3ReceiptWriter(writer)
			var wire strings.Builder
			var snapshots [][]v3.Action
			out := receiptObservationWriter{out: &wire, before: func() {
				actions, err := decodeMCPMatrixReceiptFiles(writerOpts.Dir, true)
				if err != nil {
					t.Error(err)
				}
				snapshots = append(snapshots, actions)
			}}
			input := strings.NewReader(jsonToolsCallEcho + "\n")
			var err error
			switch name {
			case "stdio", "sandbox":
				args := []string{"sh", "-c", "IFS= read -r line && printf '%s\\n' \"$1\" \"$2\"", "peer", invalid, clientRPCReply}
				if name == "stdio" {
					err = RunProxy(ctx, input, out, io.Discard, args, opts)
				} else {
					child := exec.CommandContext(ctx, "sh", "-c", "IFS= read -r line && printf '%s\\n' \"$1\" \"$2\"", "peer", invalid, clientRPCReply)
					err = runProxyWithSandbox(ctx, child, child.Start, input, out, io.Discard, opts)
				}
			case "WebSocket":
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					conn, _, _, err := ws.UpgradeHTTP(r, w)
					if err != nil {
						t.Error(err)
						return
					}
					defer func() { _ = conn.Close() }()
					if _, _, err := wsutil.ReadClientData(conn); err != nil {
						t.Error(err)
						return
					}
					for _, msg := range []string{invalid, clientRPCReply} {
						if err := wsutil.WriteServerMessage(conn, ws.OpText, []byte(msg)); err != nil {
							t.Error(err)
						}
					}
				}))
				defer server.Close()
				rd, wr := io.Pipe()
				defer func() { _ = rd.Close(); _ = wr.Close() }()
				go func() { _, _ = io.Copy(wr, input) }()
				err = RunWSProxy(ctx, rd, out, io.Discard, wsURL(server), opts)
			case "HTTP bridge":
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = fmt.Fprintf(w, "data: %s\n\ndata: %s\n\n", invalid, clientRPCReply)
				}))
				defer server.Close()
				err = RunHTTPProxy(ctx, input, out, io.Discard, server.URL, nil, opts)
			}
			if err != nil {
				t.Fatal(err)
			}
			messages := strings.Split(strings.TrimSpace(wire.String()), "\n")
			if len(messages) != 2 || messages[1] != clientRPCReply || len(snapshots) != 2 {
				t.Fatalf("wire replies = %q, writes = %d", messages, len(snapshots))
			}
			assertLocalMCPErrors(t, messages[0], "1")
			actions := verifiedMCPV3RegressionActions(t, writer, writerOpts)
			var parent string
			for _, a := range actions {
				if a.Phase == "intent" && a.EffectBoundary == mcpUpstreamSendBoundary && a.RequestID == "1" {
					parent = a.ActionID
				}
			}
			if parent == "" {
				t.Fatal("send intent missing")
			}
			if err := checkMCPWireObservations(actions, mcpDownstreamDeliveryBoundary, []mcpWireObservation{
				{message: []byte(messages[0]), before: snapshots[0], boundary: mcpDownstreamDeliveryBoundary, requestID: "1", outcome: "completed"},
				{message: []byte(messages[1]), before: snapshots[1], boundary: mcpDownstreamDeliveryBoundary, parent: parent, requestID: "1", outcome: "completed"},
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMCPV3RefusesDeferOnUnsupportedTransports(t *testing.T) {
	for _, name := range []string{"WebSocket", "HTTP listener"} {
		t.Run(name, func(t *testing.T) {
			surface := transportMCPStdio
			switch name {
			case "WebSocket":
				surface = deferred.SurfaceMCPWS
			case "HTTP listener":
				surface = deferred.SurfaceMCPHTTPListener
			}
			writer, writerOpts := openMCPV3RegressionWriter(t, surface)
			opts := nativeDeferredOptions(t, nil)
			// This fixture exercises refusal, independent of the native
			// capacity fixture's short finalization budget.
			opts.ListenerShutdownTimeout = 0
			opts = opts.WithV3ReceiptWriter(writer)
			opts.Transport = surface
			journal := filepath.Join(t.TempDir(), "journal.jsonl")
			opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Minute, JournalPath: journal})
			notification := strings.Replace(heldNativeCall, "\"id\":1,", "", 1)
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(4*time.Second))
			defer cancel()
			var out strings.Builder
			var proxyLog lockedHTTPBuffer
			input := strings.NewReader(heldNativeCall + "\n" + notification + "\n")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if surface != deferred.SurfaceMCPWS {
					t.Error("deferred message reached upstream")
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				conn, _, _, err := ws.UpgradeHTTP(r, w)
				if err != nil {
					t.Error(err)
					return
				}
				defer func() { _ = conn.Close() }()
				if msg, _, err := wsutil.ReadClientData(conn); err == nil {
					t.Errorf("deferred message reached upstream: %s", msg)
				}
			}))
			defer srv.Close()
			var err error
			switch name {
			case "WebSocket":
				err = RunWSProxy(ctx, input, &out, &proxyLog, wsURL(srv), opts)
			case "HTTP listener":
				url, _ := startListenerProxyWithOpts(t, srv.URL, opts)
				for _, msg := range []string{heldNativeCall, notification} {
					headers := http.Header{"Content-Type": {"application/json"}}
					status, _, response := postWireContractRequest(t, url, msg, headers)
					if msg == notification {
						if response != "" || status != http.StatusAccepted {
							t.Fatalf("notification response = %d %q", status, response)
						}
					} else {
						out.WriteString(response)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			var reply rpcError
			if err := json.Unmarshal([]byte(out.String()), &reply); err != nil ||
				reply.Error.Code != -32002 || canonicalID(reply.ID) != "1" {
				t.Fatalf("defer refusal = %q (%v)", out.String(), err)
			}
			if journalBytes, err := os.ReadFile(filepath.Clean(journal)); len(journalBytes) != 0 || (err != nil && !errors.Is(err, os.ErrNotExist)) {
				t.Fatalf("deferred journal wrote %d bytes (%v)", len(journalBytes), err)
			}
			if opts.DeferManager.HeldCount() != 0 {
				t.Fatal("unsupported transport registered a hold")
			}
			var refused []string
			for _, a := range verifiedMCPV3RegressionActions(t, writer, writerOpts) {
				if a.EffectBoundary == mcpUpstreamSendBoundary || a.Hold != nil {
					t.Fatalf("unexpected release or hold: %+v", a)
				}
				if a.Phase == "decision" && a.Verdict == "block" && a.EffectBoundary == mcpDownstreamDeliveryBoundary {
					refused = append(refused, a.RequestID)
				}
			}
			if !slices.Equal(refused, []string{"1", ""}) {
				t.Fatalf("signed refusals = %v, proxy log = %q", refused, proxyLog.String())
			}
		})
	}
}

func TestMCPV3BridgeDiscoverySettlesNonOKRoundTrip(t *testing.T) {
	opts, writer, observer := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, deferred.SurfaceMCPHTTPUpstream)
	observed := make(chan mcpWireObservation, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		frame := ParseMCPFrame(body)
		if frame.Method != "tools/list" {
			t.Errorf("unexpected discovery method %q", frame.Method)
		}
		before, err := decodeMCPMatrixReceiptFiles(observer.dir, true)
		if err != nil {
			t.Error(err)
		}
		select {
		case observed <- mcpWireObservation{
			message: body, before: before, boundary: mcpUpstreamSendBoundary, requestID: canonicalID(frame.ID), outcome: "completed",
		}:
		default:
			t.Error("unexpected extra private discovery request")
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	var out strings.Builder
	if err := RunHTTPProxy(t.Context(), currentWireBodyReader(), &out, io.Discard, server.URL, nil, opts); err != nil {
		t.Fatal(err)
	}
	assertLocalMCPErrors(t, strings.TrimSpace(out.String()), "2")
	actions := localMCPReceiptActions(t, writer, observer.dir)
	select {
	case observation := <-observed:
		if err := checkMCPWireObservations(actions, mcpUpstreamSendBoundary, []mcpWireObservation{observation}); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("private discovery did not reach the upstream")
	}
}
