// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

const secondSSEMethod = "notifications/resources/list_changed"

func TestMCPV3SecondSSEEventRequiresItsOwnAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, method, surface, first string
	}{
		{"listener GET", http.MethodGet, deferred.SurfaceMCPHTTPListener, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}"},
		{"listener POST", http.MethodPost, deferred.SurfaceMCPHTTPListener, clientRPCReply},
		{"bridge GET", http.MethodGet, deferred.SurfaceMCPHTTPUpstream, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}"},
	} {
		for _, required := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/required=%t", tc.name, required), func(t *testing.T) {
				row := v3MCPMatrixRow{required: required, scenario: "second SSE intent write fail"}
				writerOpts := mcpMatrixWriterOptions(t, row, tc.surface, nil, nil)
				writer, err := v3.OpenStreamWriter(t.Context(), writerOpts)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = writer.Close(context.Background(), nil) })
				opts := (MCPProxyOpts{Transport: tc.surface, Scanner: testScannerWithAction(t, config.ActionBlock)}).WithV3ReceiptWriter(writer)
				event2 := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"method\":%q}", secondSSEMethod)
				upstreamReceipts := make(chan []v3.Action, 1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamBefore, err := decodeMCPMatrixReceiptFiles(writerOpts.Dir, true)
					if err != nil {
						t.Error(err)
					}
					upstreamReceipts <- upstreamBefore
					if r.Method != tc.method {
						t.Errorf("unexpected upstream method %s", r.Method)
					}
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = fmt.Fprintf(w, "data: %s\n\ndata: %s\n\n", tc.first, event2)
				}))
				defer server.Close()

				var before [][]v3.Action
				var mu sync.Mutex
				recordWrite := func() {
					actions, err := decodeMCPMatrixReceiptFiles(writerOpts.Dir, true)
					if err != nil {
						t.Error(err)
					}
					mu.Lock()
					defer mu.Unlock()
					before = append(before, actions)
				}
				var events []string
				if tc.surface == deferred.SurfaceMCPHTTPUpstream {
					var wire bytes.Buffer
					out := &syncWriter{w: receiptObservationWriter{out: &wire, before: recordWrite}}
					scanErr, setupErr := scanGETStream(t.Context(), transport.NewHTTPClient(server.URL, nil), out, io.Discard, opts, nil)
					if !errors.Is(scanErr, errMCPV3ReplyAdmission) || setupErr != nil {
						t.Fatalf("GET stream returned scan=%v, setup=%v", scanErr, setupErr)
					}
					events = strings.Split(strings.TrimSpace(wire.String()), "\n")
				} else {
					ln := newListenerProxyTestListener(t)
					var armed atomic.Bool
					listener := mcpMatrixWriteListener{Listener: ln, beforeWrite: func() {
						if armed.Load() {
							recordWrite()
						}
					}}
					ctx, stop := context.WithCancel(t.Context())
					done := make(chan error, 1)
					go func(l net.Listener) { done <- RunHTTPListenerProxy(ctx, l, server.URL, io.Discard, opts) }(listener)
					stopListener := sync.OnceFunc(func() { stop(); waitForListenerProxyStop(t, done) })
					defer stopListener()
					url := "http://" + ln.Addr().String()
					waitForHTTPHealth(t, url)
					armed.Store(true)
					var body io.Reader
					if tc.method == http.MethodPost {
						body = strings.NewReader(jsonToolsCallEcho)
					}
					req, err := http.NewRequestWithContext(ctx, tc.method, url, body)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Accept", "text/event-stream")
					req.Header.Set("Content-Type", "application/json")
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					data, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("listener returned HTTP %d: %s", resp.StatusCode, data)
					}
					events = readReceiptSSEEvents(t, data)
					stopListener()
				}
				if !slices.Equal(events, []string{tc.first}) {
					t.Fatalf("wire events = %q", events)
				}
				mu.Lock()
				defer mu.Unlock()
				if len(before) == 0 {
					t.Fatal("no pre-write observation")
				}
				actions := verifyMCPFailedStreamFixture(t, writer, writerOpts)
				upstreamBefore := <-upstreamReceipts
				var parent, id string
				if tc.method == http.MethodPost {
					id = "1"
					for _, a := range upstreamBefore {
						if a.Phase == "intent" && a.EffectBoundary == mcpUpstreamSendBoundary && a.RequestID == id {
							parent = a.ActionID
						}
					}
					if parent == "" {
						t.Fatal("POST arrived without its own send intent")
					}
					if err := checkMCPWireObservations(actions, mcpUpstreamSendBoundary, []mcpWireObservation{{
						message: []byte(jsonToolsCallEcho), before: upstreamBefore, boundary: mcpUpstreamSendBoundary, requestID: id, outcome: "completed",
					}}); err != nil {
						t.Fatal(err)
					}
				}
				if err := checkMCPWireObservations(actions, mcpDownstreamDeliveryBoundary, []mcpWireObservation{{
					message: []byte(events[0]), before: before[0], boundary: mcpDownstreamDeliveryBoundary,
					parent: parent, requestID: id, outcome: "completed",
				}}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

type receiptObservationWriter struct {
	out    io.Writer
	before func()
}

func (w receiptObservationWriter) Write(p []byte) (int, error) {
	w.before()
	return w.out.Write(p)
}

func readReceiptSSEEvents(t *testing.T, data []byte) []string {
	t.Helper()
	var events []string
	reader := transport.NewSSEReader(bytes.NewReader(data))
	for {
		event, err := reader.ReadMessage()
		if errors.Is(err, io.EOF) {
			return events
		}
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, string(event))
	}
}

func verifyMCPFailedStreamFixture(t *testing.T, writer *v3.StreamWriter, opts v3.StreamWriterOptions) []v3.Action {
	t.Helper()
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	verified, err := v3.VerifyPaths(t.Context(), []string{opts.Dir}, v3.Options{
		Directory: true, Keys: []ed25519.PublicKey{opts.SigningKey.Public().(ed25519.PublicKey)},
	})
	if err != nil || verified.Integrity != "ok" || verified.Verdict != "VALID PREFIX, END UNPROVEN" {
		t.Fatalf("receipt verification = %s, integrity %s (%v)", verified.Verdict, verified.Integrity, err)
	}
	var endUnproven bool
	for _, finding := range verified.Findings {
		switch finding.Code {
		case "END_UNPROVEN":
			endUnproven = true
		case "UNCONFIRMED":
			// The earlier outcome can land before the admission write fails,
			// then replay on the successor.
		default:
			t.Fatalf("unexpected verification finding: %+v", finding)
		}
	}
	if !endUnproven {
		t.Fatal("missing END_UNPROVEN finding")
	}
	actions, err := readMCPMatrixActions(opts.Dir)
	if err != nil {
		t.Fatal(err)
	}
	return actions
}
