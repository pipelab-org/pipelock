// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// A cancelled upstream can finish its chunked body while the proxy is reading.
// The completed event stays delivered, but EOF must not hide the cancellation.
func TestSSEStreamIntegrityCancelledEOF(t *testing.T) {
	sc := testScannerForHTTP(t)
	payload := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":{\"state\":\"working\"}}}\n\n"
	for _, mode := range []string{"a2a", "generic", "passthrough"} {
		for _, cancelled := range []bool{false, true} {
			t.Run(mode+"/cancelled="+strconv.FormatBool(cancelled), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var body io.Reader = strings.NewReader(payload)
				if cancelled {
					body = &integrityCancelEOFReader{Reader: body, cancel: cancel}
				}
				var out bytes.Buffer
				var err error
				switch mode {
				case "a2a":
					err = ScanA2AStream(ctx, body, &out, nil, sc, &config.A2AScanning{Enabled: true, Action: config.ActionBlock})
				case "generic":
					err = ScanGenericSSEStream(ctx, body, &out, nil, sc, &config.GenericSSEScanning{Enabled: true, Action: config.ActionBlock})
				default:
					err = passthroughSSE(ctx, body, &out, nil)
				}
				if cancelled {
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancelled EOF returned %v, want context.Canceled", err)
					}
				} else if err != nil {
					t.Fatalf("complete stream returned %v", err)
				}
				if out.String() != payload {
					t.Fatalf("delivered event = %q, want %q", out.String(), payload)
				}
			})
		}
	}
}

type integrityCancelEOFReader struct {
	io.Reader
	cancel context.CancelFunc
}

func (r *integrityCancelEOFReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		r.cancel()
	}
	return n, err
}

// The MCP listener serves plain HTTP/1; it does not negotiate HTTP/2. Exercise
// its actual server, rather than a recorder that cannot observe chunk framing.
func TestMCPListenerStreamIntegrity(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		for _, ending := range []string{"chunked_break", "short_length", "completed_rpc_then_break", "cancel", "handler_cancel", "complete"} {
			t.Run(method+"/"+ending, func(t *testing.T) {
				if method == http.MethodGet && ending == "completed_rpc_then_break" {
					t.Skip("GET subscriptions carry notifications rather than client request results")
				}
				payload := "data: " + jsonProgressNotification50 + "\n\n"
				if method == http.MethodPost && (ending == "complete" || ending == "completed_rpc_then_break") {
					payload += "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"hello\"}]}}\n\n"
				}
				release := make(chan struct{})
				var releaseOnce sync.Once
				releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
				upstreamDone := make(chan struct{})
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(upstreamDone)
					w.Header().Set("Content-Type", "text/event-stream")
					if ending == "short_length" || ending == "handler_cancel" {
						// Outstanding declared bytes keep the stream open until the
						// handler is cancelled, even after the event is delivered.
						w.Header().Set("Content-Length", strconv.Itoa(len(payload)+1024))
					}
					_, _ = io.WriteString(w, payload)
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
					if ending == "chunked_break" || ending == "completed_rpc_then_break" {
						panic(http.ErrAbortHandler)
					}
				}))
				h := newMCPDecisionReceiptHarness(t)
				auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
				logger, err := audit.New("json", "file", auditPath, false, false)
				if err != nil {
					t.Fatal(err)
				}
				ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancelListener := context.WithCancel(t.Context())
				listenerDone := make(chan error, 1)
				sc := testScannerForHTTP(t)
				handlerCancel := make(chan context.CancelFunc, 1)
				opts := MCPProxyOpts{
					Scanner: sc, ReceiptEmitter: h.v1, AuditLogger: logger, RequireReceipts: true,
				}
				if ending == "handler_cancel" {
					// The resolver sees the server request before upstream forwarding.
					// Give its handler a cancellable context without closing the
					// downstream connection or cancelling the client's request.
					opts.ListenerPrincipalResolver = func(r *http.Request) (ListenerPrincipal, error) {
						ctx, cancelHandler := context.WithCancel(r.Context())
						t.Cleanup(cancelHandler)
						*r = *r.WithContext(ctx)
						handlerCancel <- cancelHandler
						return ListenerPrincipal{}, nil
					}
				}
				go func() {
					listenerDone <- RunHTTPListenerProxy(ctx, ln, upstream.URL, io.Discard, opts)
				}()
				t.Cleanup(func() {
					releaseUpstream()
					cancelListener()
					_ = ln.Close()
					upstream.Close()
					logger.Close()
				})
				baseURL := "http://" + ln.Addr().String()
				waitForHTTPHealth(t, baseURL)
				requestCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				var requestBody io.Reader
				if method == http.MethodPost {
					requestBody = strings.NewReader(jsonToolsCallEcho)
				}
				req, err := http.NewRequestWithContext(requestCtx, method, baseURL+"/", requestBody)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "text/event-stream")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("before upstream break: %v", err)
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 1 {
					body, _ := io.ReadAll(resp.Body)
					t.Fatalf("status=%d protocol=%s body=%s", resp.StatusCode, resp.Proto, body)
				}
				first := make([]byte, len(payload))
				if _, err := io.ReadFull(resp.Body, first); err != nil {
					t.Fatal(err)
				}
				if string(first) != payload {
					t.Fatalf("event = %s", first)
				}
				switch ending {
				case "cancel":
					cancel()
				case "handler_cancel":
					cancelHandler := <-handlerCancel
					cancelHandler()
				default:
					releaseUpstream()
				}
				_, readErr := io.ReadAll(resp.Body)
				if (readErr == nil) != (ending == "complete") {
					t.Fatalf("read error = %v, ending = %s", readErr, ending)
				}
				if ending == "handler_cancel" && requestCtx.Err() != nil {
					t.Fatalf("client context ended before server abort: %v", requestCtx.Err())
				}
				select {
				case <-upstreamDone:
				case <-time.After(5 * time.Second):
					t.Fatal("upstream did not end after downstream cancellation")
				}
				cancelListener()
				select {
				case err := <-listenerDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(6 * time.Second):
					t.Fatal("listener handler did not end")
				}
				if err := h.rec.Close(); err != nil {
					t.Fatal(err)
				}
				receipts := readActionReceipts(t, h.dir)
				wantReason := httpstream.Incomplete
				if ending == "cancel" || ending == "handler_cancel" {
					wantReason = httpstream.Cancelled
				}
				if method == http.MethodGet {
					if len(receipts) != 2 {
						t.Fatalf("GET receipt count = %d, want admission and terminal", len(receipts))
					}
					verdict, pattern := config.ActionWarn, "status=error bytes=unknown reason="+wantReason
					if ending == "complete" {
						verdict, pattern = config.ActionForward, completedMCPStreamPattern
					}
					assertMCPTransportReceiptPair(t, receipts[0].ActionRecord, receipts[1].ActionRecord,
						receipt.ActionRecord{
							Method: http.MethodGet, Transport: "mcp_http_listener", Target: upstream.URL,
							Verdict: verdict, Pattern: pattern,
						})
				} else {
					assertMCPListenerPOSTOutcomes(t, receipts, ending, wantReason)
				}
				logger.Close()
				logBytes, err := os.ReadFile(filepath.Clean(auditPath))
				if err != nil {
					t.Fatal(err)
				}
				wantAudit := ending != "cancel" && ending != "handler_cancel" && ending != "complete"
				if got := strings.Contains(string(logBytes), "response stream incomplete"); got != wantAudit {
					t.Fatalf("incomplete audit=%v want=%v: %s", got, wantAudit, logBytes)
				}
			})
		}
	}
}

func assertMCPListenerPOSTOutcomes(t *testing.T, receipts []receipt.Receipt, ending, wantReason string) {
	t.Helper()
	found := false
	var intentID string
	outcomes := make(map[string]string)
	for _, rec := range receipts {
		switch rec.ActionRecord.DecisionPhase {
		case receipt.DecisionPhaseIntent:
			if intentID != "" {
				t.Fatal("multiple request intents")
			}
			intentID = rec.ActionRecord.ActionID
		case receipt.DecisionPhaseOutcome:
			if _, exists := outcomes[rec.ActionRecord.ActionID]; exists {
				t.Fatalf("duplicate outcome for action %s", rec.ActionRecord.ActionID)
			}
			outcomes[rec.ActionRecord.ActionID] = rec.ActionRecord.Pattern
		}
		if rec.ActionRecord.Layer == mcpOutcomeLayer && strings.Contains(rec.ActionRecord.Pattern, "reason="+wantReason) {
			found = true
		}
	}
	if ending != "complete" && !found {
		t.Fatalf("missing %s outcome: %+v", wantReason, receipts)
	}
	if ending == "complete" || ending == "completed_rpc_then_break" {
		if !strings.HasPrefix(outcomes[intentID], "status=result ") || (ending == "complete" && len(outcomes) != 1) {
			t.Fatalf("completed POST intent %q must have one result outcome, got %v", intentID, outcomes)
		}
	} else if len(outcomes) != 1 || !strings.HasSuffix(outcomes[intentID], "reason="+wantReason) {
		t.Fatalf("interrupted POST intent %q must have one matching %s outcome, got %v", intentID, wantReason, outcomes)
	}
}
