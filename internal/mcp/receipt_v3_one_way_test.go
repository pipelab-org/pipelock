// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
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

func TestMCPV3ClientReplyShortWriteRemainsUnknown(t *testing.T) {
	opts, writer, observer := localMCPReceiptFixture(t, v3MCPMatrixRow{required: true}, transportMCPStdio)
	opts = opts.withV3Session()
	ForwardScannedInput(transport.NewStdioReader(strings.NewReader(clientRPCReply+"\n")),
		transport.NewStdioWriter(shortReplyWriter{}), io.Discard, config.ActionWarn, config.ActionBlock,
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

type partialHTTPWriteConn struct{ net.Conn }

func (c partialHTTPWriteConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p[:len(p)/2])
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
	opts.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return partialHTTPWriteConn{Conn: conn}, nil
	}
	if err := RunHTTPProxy(t.Context(), strings.NewReader(clientRPCReply+"\n"), io.Discard, io.Discard,
		upstream.URL, nil, opts); err != nil {
		t.Fatal(err)
	}
	actions := localMCPReceiptActions(t, writer, observer.dir)
	if len(actions) != 2 || actions[1].OutcomeClass != "attempt_unknown" {
		t.Fatalf("partial HTTP send receipts = %+v", actions)
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
