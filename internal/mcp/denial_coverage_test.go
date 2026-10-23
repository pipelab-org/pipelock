// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func assertDenialRoute(t *testing.T, events, label, class, resource, direction string) {
	t.Helper()
	if strings.Count(events, `"event":"blocked"`) != 1 {
		t.Fatalf("want exactly one blocked event: %s", events)
	}
	for _, field := range []string{`"scanner":"` + label + `"`, `"block_class":"` + class + `"`, `"resource":"` + resource + `"`, `"direction":"` + direction + `"`} {
		if !strings.Contains(events, field) {
			t.Fatalf("missing %s: %s", field, events)
		}
	}
}

func TestMCPBridgeStartupEvaluationDenial(t *testing.T) {
	for _, surface := range []string{"http", "ws", "listener"} {
		t.Run(surface, func(t *testing.T) {
			logger, events := newListenerEventLogger(t)
			// A loaded contract requires a scanner. Refuse before dialing if the
			// scanner prerequisite is missing, even with no client message available.
			opts := MCPProxyOpts{AuditLogger: logger, ContractLoader: mcpLiveLockLoader(t, contractruntime.ModeLive, mcpToolRule("allow", nil))}
			dials := 0
			opts.DialContext = func(context.Context, string, string) (net.Conn, error) {
				dials++
				t.Error("dial after failed evaluation")
				return nil, io.ErrClosedPipe
			}
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(3*time.Second))
			defer cancel()
			var out bytes.Buffer
			var err error
			switch surface {
			case "http":
				err = RunHTTPProxy(ctx, strings.NewReader(""), &out, io.Discard, "http://api.vendor.example/mcp", nil, opts)
			case "ws":
				err = RunWSProxy(ctx, strings.NewReader(""), &out, io.Discard, "ws://api.vendor.example/mcp", opts)
			case "listener":
				var lc net.ListenConfig
				ln, listenErr := lc.Listen(ctx, "tcp", "127.0.0.1:0")
				if listenErr != nil {
					t.Fatal(listenErr)
				}
				defer func() { _ = ln.Close() }()
				err = RunHTTPListenerProxy(ctx, ln, "http://api.vendor.example/mcp", io.Discard, opts)
			}
			if err == nil || !strings.Contains(err.Error(), "scanner unavailable") || out.Len() != 0 || dials != 0 {
				t.Fatalf("err=%v output=%q dials=%d", err, out.String(), dials)
			}
			assertDenialRoute(t, events.String(), scanner.AuditContract, audit.BlockClassInfrastructureError, mcpResourceStartup, "startup")
		})
	}
}

func TestMCPMediaInspectionDenialWire(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"invalid_base64", `{"type":"image","mimeType":"image/png","data":"!invalid!"}`},
		{"unsupported_media", `{"type":"image","data":"eA=="}`},
		{"invalid_image", `{"type":"image","mimeType":"image/png","data":"iVBORw0KGgo="}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, cfg := newMCPScannerWithMediaPolicy(t)
			logger, events := newListenerEventLogger(t)
			line := `{"jsonrpc":"2.0","id":71,"result":{"content":[` + tc.content + `]}}`
			var out bytes.Buffer
			_, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(line+"\n")), transport.NewStdioWriter(&out), io.Discard, nil, MCPProxyOpts{Scanner: sc, MediaPolicy: &cfg.MediaPolicy, AuditLogger: logger})
			if err != nil {
				t.Fatal(err)
			}
			var reply struct {
				ID    int `json:"id"`
				Error *struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &reply); err != nil {
				t.Fatal(err)
			}
			if reply.ID != 71 || reply.Error == nil || reply.Error.Code != -32002 || strings.Contains(out.String(), `"result"`) {
				t.Fatalf("unsafe media reply: %s", out.String())
			}
			assertDenialRoute(t, events.String(), scanner.AuditMediaPolicy, audit.BlockClassInfrastructureError, "[redacted]", "response")
		})
	}
	testMCPMediaNonContentResponses(t)
}

type refusedReplyWriter struct{ calls int }

func (w *refusedReplyWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, io.ErrClosedPipe
}

func TestMCPBridgeDispositionDelivery(t *testing.T) {
	testMCPBridgeKillDelivery(t)
	if runtime.GOOS == osWindows {
		t.Skip("redirect command requires Unix")
	}
	for _, surface := range []string{"http", "ws"} {
		for _, disposition := range []string{"redirect", "redirect_notification", "redirect_write_error", "denial_write_error"} {
			t.Run(surface+"/"+disposition, func(t *testing.T) {
				logger, events := newListenerEventLogger(t)
				action := config.ActionRedirect
				if disposition == "denial_write_error" {
					action = config.ActionBlock
				}
				opts := MCPProxyOpts{Scanner: testInputScanner(t), AuditLogger: logger, PolicyCfg: policy.New(config.MCPToolPolicy{
					Enabled: true, Action: config.ActionWarn,
					RedirectProfiles: map[string]config.RedirectProfile{"local": {Exec: []string{"/bin/echo", "local result"}}},
					Rules:            []config.ToolPolicyRule{{Name: "route", ToolPattern: "^echo$", Action: action, RedirectProfile: "local"}},
				})}
				request := makeRequest(73, methodToolsCall, map[string]any{"name": "echo", "arguments": map[string]any{}})
				if disposition == "redirect_notification" {
					request = strings.Replace(request, `"id":73,`, "", 1)
				}
				var out, logs bytes.Buffer
				failed := &refusedReplyWriter{}
				var writer io.Writer = &out
				if strings.HasSuffix(disposition, "write_error") {
					writer = failed
				}
				ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(3*time.Second))
				defer cancel()
				var err error
				if surface == "http" {
					upstream, calls := countingUpstream(t)
					err = RunHTTPProxy(ctx, strings.NewReader(request+"\n"), writer, &logs, upstream.URL, nil, opts)
					if calls.Load() != 0 {
						t.Fatalf("local disposition reached upstream: %d", calls.Load())
					}
				} else {
					upstream, frames := wsDrainServer(t)
					defer upstream.Close()
					err = RunWSProxy(ctx, strings.NewReader(request+"\n"), writer, &logs, "ws"+strings.TrimPrefix(upstream.URL, "http"), opts)
					if frames.Load() != 0 {
						t.Fatalf("local disposition reached upstream: %d", frames.Load())
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				switch disposition {
				case "denial_write_error":
					if failed.calls != 1 || !strings.Contains(logs.String(), "failed to send input result") {
						t.Fatalf("writes=%d log=%s", failed.calls, logs.String())
					}
					assertDenialRoute(t, events.String(), scanner.AuditMCPToolPolicy, audit.BlockClassProtective, mcpResourceInput, "input")
				case "redirect_write_error":
					if failed.calls != 1 || !strings.Contains(logs.String(), "synthetic response write error") {
						t.Fatalf("writes=%d log=%s", failed.calls, logs.String())
					}
				case "redirect":
					if !strings.Contains(out.String(), `"result"`) || !strings.Contains(out.String(), "local result") || strings.Contains(out.String(), `"error"`) {
						t.Fatalf("redirect reply=%s", out.String())
					}
				case "redirect_notification":
					if out.Len() != 0 {
						t.Fatalf("notification received reply: %s", out.String())
					}
				}
				if disposition != "denial_write_error" && strings.Contains(events.String(), `"event":"blocked"`) {
					t.Fatalf("successful redirect recorded denial: %s", events.String())
				}
			})
		}
	}
}

// Exercise the HTTP adapter as a streaming ResponseWriter: flushing before a
// body must finalize once, while an ordinary stream must not become a denial.
func TestMCPListenerDenialStreamingAdapter(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(strconv.FormatBool(denied), func(t *testing.T) {
			logger, events := newListenerEventLogger(t)
			descriptor := mcpDenialAudit{}
			if denied {
				descriptor = mcpListenerAdmissionDenialAudit()
			}
			recorder := httptest.NewRecorder()
			writer := &mcpListenerDenialWriter{ResponseWriter: recorder, opts: MCPProxyOpts{AuditLogger: logger}, descriptor: &descriptor}
			if writer.Unwrap() != recorder {
				t.Fatal("response controller lost underlying writer")
			}
			writer.Flush()
			n, err := writer.Write([]byte("event: refusal\n\n"))
			writer.Flush()
			if err != nil || n != len("event: refusal\n\n") || !recorder.Flushed || recorder.Code != http.StatusOK || recorder.Body.String() != "event: refusal\n\n" {
				t.Fatalf("n=%d err=%v recorder=%+v", n, err, recorder)
			}
			if denied {
				assertDenialRoute(t, events.String(), scanner.AuditMCPProtocol, audit.BlockClassProtective, mcpResourceListener, "input")
			} else if strings.Contains(events.String(), `"event":"blocked"`) {
				t.Fatal(events.String())
			}
		})
	}
}

func TestMCPInputDeliveryMissingClassificationFailsClosed(t *testing.T) {
	for _, surface := range []string{"stdio", "http"} {
		for _, notification := range []bool{false, true} {
			t.Run(surface+"/"+strconv.FormatBool(notification), func(t *testing.T) {
				logger, events := newListenerEventLogger(t)
				opts := MCPProxyOpts{AuditLogger: logger}
				br := BlockedRequest{ID: json.RawMessage(`79`), IsNotification: notification, ErrorCode: -32002, ErrorMessage: "refused"}
				var body string
				if surface == "stdio" {
					var out bytes.Buffer
					if err := deliverMCPInputResult(opts, br, transport.NewStdioWriter(&out)); err != nil {
						t.Fatal(err)
					}
					body = out.String()
				} else {
					recorder := httptest.NewRecorder()
					writeMCPHTTPInputResult(opts, br, recorder)
					body = recorder.Body.String()
					want := http.StatusOK
					if notification {
						want = http.StatusAccepted
					}
					if recorder.Code != want {
						t.Fatalf("status=%d want %d", recorder.Code, want)
					}
				}
				if notification {
					if body != "" {
						t.Fatalf("notification reply=%s", body)
					}
				} else if !strings.Contains(body, `"code":-32002`) || !strings.Contains(body, `"id":79`) || strings.Contains(body, `"result"`) {
					t.Fatalf("refusal reply=%s", body)
				}
				assertDenialRoute(t, events.String(), scanner.AuditScannerUnavailable, audit.BlockClassInfrastructureError, mcpResourceInput, "input")
			})
		}
	}
}

func TestMCPDeferredNotificationDenial(t *testing.T) {
	for _, surface := range []string{"stdio", "http"} {
		for _, cause := range []string{"operator", "kill", "receipt"} {
			t.Run(surface+"/"+cause, func(t *testing.T) {
				logger, events := newListenerEventLogger(t)
				manager := newDeferKillManager(t)
				emitter, rec, _, _ := newReceiptTestHarness(t)
				ks := deferKillTestController()
				policyCfg := deferApprovalPolicy(config.DeferResolverProfile{})
				policyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
				inputR, inputW := io.Pipe()
				defer func() { _ = inputW.Close(); _ = inputR.Close() }()
				ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
				defer cancel()
				opts := MCPProxyOpts{Scanner: testInputScanner(t), AuditLogger: logger, DeferManager: manager, PolicyCfg: policyCfg, ReceiptEmitter: emitter, RequireReceipts: true, KillSwitch: ks}
				var out, logs, upstream syncBuffer
				blocked := make(chan BlockedRequest, 4)
				done := make(chan error, 1)
				server, calls := countingUpstream(t)
				if surface == "stdio" {
					opts.Transport = deferred.SurfaceMCPStdio
					go func() {
						ForwardScannedInput(transport.NewStdioReader(inputR), transport.NewStdioWriter(&upstream), &logs, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
						done <- nil
					}()
				} else {
					go func() { done <- RunHTTPProxy(ctx, inputR, &out, &logs, server.URL, nil, opts) }()
				}
				request := strings.Replace(deferKillTestCall, `"id":1,`, "", 1)
				if _, err := io.WriteString(inputW, request); err != nil {
					t.Fatal(err)
				}
				testwait.For(t, 3*time.Second, func() bool { return len(manager.Snapshot()) == 1 }, "notification hold")
				held := manager.Snapshot()[0]
				decision, source := config.ActionBlock, deferred.SourceOperator
				label, class := scanner.AuditMCPDefer, audit.BlockClassProtective
				switch cause {
				case "kill":
					ks.SetAPI(true)
					source = deferred.SourceKillSwitch
					label = scanner.AuditKillSwitch
				case "receipt":
					_ = rec.Close()
					decision = config.ActionAllow
					label = scanner.AuditReceiptEmission
					class = audit.BlockClassInfrastructureError
				}
				if _, err := manager.ResolveApprovalResult(held.DeferID, decision, source); err != nil {
					t.Fatal(err)
				}
				if err := inputW.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatalf("proxy did not stop: %s", logs.String())
				}
				if out.String() != "" || upstream.String() != "" || len(blocked) != 0 || calls.Load() != 0 {
					t.Fatalf("notification sent reply or upstream traffic: out=%q upstream=%q blocked=%d calls=%d", out.String(), upstream.String(), len(blocked), calls.Load())
				}
				assertDenialRoute(t, events.String(), label, class, mcpResourceInput, "input")
			})
		}
	}
	testMCPDeferredAdmissionDenials(t)
}

func TestMCPStartupDenialRoutes(t *testing.T) {
	for _, surface := range []string{"http", "ws", "listener"} {
		for _, cause := range []string{"contract", "kill", "metadata"} {
			t.Run(surface+"/"+cause, func(t *testing.T) {
				logger, events := newListenerEventLogger(t)
				opts := mcpLiveLockOpts(t, contractruntime.ModeLive, contractruntimetest.HTTPEnforceRule("other-host", "other.vendor.example", "/", http.MethodPost))
				opts.AuditLogger = logger
				upstream := "http://api.vendor.example/mcp"
				label, class, resource := scanner.AuditContract, audit.BlockClassProtective, mcpResourceStartup
				if cause == "kill" {
					ks := deferKillTestController()
					ks.SetAPI(true)
					opts.KillSwitch = ks
					label = scanner.AuditKillSwitch
				}
				if cause == "metadata" {
					cfg := config.Defaults()
					cfg.Internal = []string{"169.254.0.0/16"}
					cfg.SSRF.IPAllowlist = []string{"169.254.0.0/16"}
					opts.Scanner = scanner.MustNew(cfg)
					t.Cleanup(opts.Scanner.Close)
					opts.ContractLoader = nil
					upstream = "http://169.254.169.254/mcp"
					label = scanner.ScannerSSRFMetadata
					class = audit.BlockClassThreat
					resource = mcpResourceInput
				}
				var dials atomic.Int32
				opts.DialContext = func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, io.ErrClosedPipe }
				ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(3*time.Second))
				defer cancel()
				var out bytes.Buffer
				var err error
				switch surface {
				case "http":
					err = RunHTTPProxy(ctx, strings.NewReader(""), &out, io.Discard, upstream, nil, opts)
				case "ws":
					err = RunWSProxy(ctx, strings.NewReader(""), &out, io.Discard, "ws"+strings.TrimPrefix(upstream, "http"), opts)
				case "listener":
					var lc net.ListenConfig
					ln, listenErr := lc.Listen(ctx, "tcp", "127.0.0.1:0")
					if listenErr != nil {
						t.Fatal(listenErr)
					}
					defer func() { _ = ln.Close() }()
					err = RunHTTPListenerProxy(ctx, ln, upstream, io.Discard, opts)
				}
				if err == nil || !strings.Contains(err.Error(), "contract upstream denied") || dials.Load() != 0 || out.Len() != 0 {
					t.Fatalf("startup err=%v dials=%d output=%q", err, dials.Load(), out.String())
				}
				assertDenialRoute(t, events.String(), label, class, resource, "startup")
			})
		}
	}
}

func TestMCPInputFragmentOwnerDenial(t *testing.T) {
	buffer := scanner.NewFragmentBuffer(1024, 10, testMCPWindowSecs)
	t.Cleanup(buffer.Close)
	cee := &CEEDeps{Buffer: buffer, Config: &config.CrossRequestDetection{Enabled: true, Action: config.ActionBlock, FragmentReassembly: config.CrossRequestFragments{Enabled: true, MaxBufferBytes: 1024, WindowMinutes: testMCPWindowSecs / 60}}}
	sc := testMCPScanner()
	t.Cleanup(sc.Close)
	logger, events := newListenerEventLogger(t)
	opts := MCPProxyOpts{Scanner: sc, AuditLogger: logger, CEE: cee}
	request := []byte(`{"jsonrpc":"2.0","id":81,"method":"resources/read","params":{"uri":"file:///work/status"}}`)
	// Positive control: the same frame and session are allowed before the
	// conflicting owner is seeded, so a stopped pipeline cannot satisfy this.
	if got := scanHTTPInputDecision(request, io.Discard, "session-001", "audit", opts); got.Blocked != nil || !bytes.Equal(got.ForwardMessage, request) {
		t.Fatalf("unclaimed stream refused: %+v", got.Blocked)
	}
	buffer.Close()
	foreign := identitykey.NewMCPCEEIdentity("session")
	if got := buffer.AppendOwned(foreign, foreign.Stream("-001"), []byte("foreign")); got.OwnerMismatch {
		t.Fatal("could not seed conflicting stream")
	}
	got := scanHTTPInputDecision(request, io.Discard, "session-001", "audit", opts)
	if got.Blocked == nil || got.Blocked.ErrorCode != mcpCEEBlockErrorCode {
		t.Fatalf("foreign stream admitted: %+v", got)
	}
	reply := httptest.NewRecorder()
	writeMCPHTTPInputResult(opts, *got.Blocked, reply)
	if reply.Code != http.StatusOK || !strings.Contains(reply.Body.String(), `"id":81`) || !strings.Contains(reply.Body.String(), `"code":-32005`) {
		t.Fatalf("owner denial reply=%d %s", reply.Code, reply.Body.String())
	}
	assertDenialRoute(t, events.String(), scanner.AuditCrossRequestFragmentOwnerMismatch, audit.BlockClassProtective, "[redacted]", "input")
}

func TestMCPListenerAmbiguousRoutingDenial(t *testing.T) {
	logger, events := newListenerEventLogger(t)
	upstream, calls := countingUpstream(t)
	base, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t), AuditLogger: logger})
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(3*time.Second))
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base, strings.NewReader(makeRequest(83, methodToolsCall, map[string]any{"name": "echo"})))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Add(listenerMCPMethod, methodToolsCall)
	request.Header.Add(listenerMCPMethod, "tools/list")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "invalid MCP routing header") || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d body=%s", response.StatusCode, calls.Load(), body)
	}
	assertDenialRoute(t, events.String(), scanner.AuditMCPProtocol, audit.BlockClassProtective, mcpResourceListener, "input")
}

// A hot reload may disable the manager after the scan has written its defer
// intent. The bridge must refuse that already-scanned disposition as well.
func testMCPDeferredAdmissionDenials(t *testing.T) {
	for _, cause := range []string{"capacity", "stdio_capacity", "disabled_after_scan"} {
		for _, notification := range []bool{false, true} {
			t.Run(cause+"/"+strconv.FormatBool(notification), func(t *testing.T) {
				logger, events := newListenerEventLogger(t)
				manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Hour, MaxPending: 1, MaxPendingPerSession: 1, MaxPendingBytes: 4096})
				if strings.HasSuffix(cause, "capacity") {
					if err := manager.Hold(deferred.HeldAction{DeferID: "occupied", ActionID: "occupied", Target: "echo", SizeBytes: 1, Resolve: func(deferred.Resolution) {}}); err != nil {
						t.Fatal(err)
					}
				}
				var disabled atomic.Bool
				emitter, _, _, _ := newReceiptTestHarnessWithObserver(t, func(r *receipt.Receipt) {
					if r != nil && r.ActionRecord.DecisionPhase == receipt.DecisionPhaseDefer {
						disabled.Store(true)
					}
				})
				policyCfg := deferApprovalPolicy(config.DeferResolverProfile{})
				policyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
				opts := MCPProxyOpts{Scanner: testInputScanner(t), AuditLogger: logger, ReceiptEmitter: emitter, PolicyCfg: policyCfg, DeferManagerFn: func() *deferred.Manager {
					if cause == "disabled_after_scan" && disabled.Load() {
						return nil
					}
					return manager
				}}
				server, calls := countingUpstream(t)
				request := deferKillTestCall
				if notification {
					request = strings.Replace(request, `"id":1,`, "", 1)
				}
				var out, logs bytes.Buffer
				ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(3*time.Second))
				defer cancel()
				if cause == "stdio_capacity" {
					opts.Transport = deferred.SurfaceMCPStdio
					blocked := make(chan BlockedRequest, 1)
					var forwarded bytes.Buffer
					ForwardScannedInput(transport.NewStdioReader(strings.NewReader(request)), transport.NewStdioWriter(&forwarded), &logs, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
					if forwarded.Len() != 0 {
						t.Fatalf("capacity refusal forwarded: %s", forwarded.String())
					}
					for br := range blocked {
						if err := deliverMCPInputResult(opts, br, transport.NewStdioWriter(&out)); err != nil {
							t.Fatal(err)
						}
					}
				} else if err := RunHTTPProxy(ctx, strings.NewReader(request), &out, &logs, server.URL, nil, opts); err != nil {
					t.Fatal(err)
				}
				class := audit.BlockClassProtective
				if cause == "disabled_after_scan" {
					class = audit.BlockClassConfigMismatch
					if !disabled.Load() {
						t.Fatal("defer intent did not reach reload boundary")
					}
				}
				if calls.Load() != 0 {
					t.Fatalf("refused call reached upstream: %d", calls.Load())
				}
				if notification {
					if out.Len() != 0 {
						t.Fatalf("notification reply=%s", out.String())
					}
				} else if !strings.Contains(out.String(), `"code":-32002`) {
					t.Fatalf("admission reply=%s", out.String())
				}
				assertDenialRoute(t, events.String(), scanner.AuditMCPDefer, class, mcpResourceInput, "input")
			})
		}
	}
}

func testMCPMediaNonContentResponses(t *testing.T) {
	for _, result := range []string{`[]`, `{"content":[]}`, `{"content":"safe"}`} {
		t.Run("non_media_"+result, func(t *testing.T) {
			sc, cfg := newMCPScannerWithMediaPolicy(t)
			logger, events := newListenerEventLogger(t)
			line := `{"jsonrpc":"2.0","id":89,"result":` + result + `}`
			var out bytes.Buffer
			found, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(line+"\n")), transport.NewStdioWriter(&out), io.Discard, nil, MCPProxyOpts{Scanner: sc, MediaPolicy: &cfg.MediaPolicy, AuditLogger: logger})
			if err != nil || found || strings.TrimSpace(out.String()) != line || strings.Contains(events.String(), `"event":"blocked"`) {
				t.Fatalf("non-media reply changed: found=%v err=%v out=%s events=%s", found, err, out.String(), events.String())
			}
		})
	}
}

type denialActivationReader struct {
	io.Reader
	activate func()
}

func (r *denialActivationReader) Read(p []byte) (int, error) {
	if r.activate != nil {
		r.activate()
		r.activate = nil
	}
	return r.Reader.Read(p)
}

func testMCPBridgeKillDelivery(t *testing.T) {
	for _, surface := range []string{"http", "ws", "stdio"} {
		for _, disposition := range []string{"batch", "batch_write_error", "request", "request_write_error", "notification"} {
			t.Run(surface+"/kill_"+disposition, func(t *testing.T) {
				logger, events := newListenerEventLogger(t)
				ks := deferKillTestController()
				opts := MCPProxyOpts{Scanner: testInputScanner(t), KillSwitch: ks, AuditLogger: logger}
				request := `{"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
				if disposition == "notification" {
					request = strings.Replace(request, `"id":91,`, "", 1)
				} else if strings.HasPrefix(disposition, "batch") {
					request = "[" + request + "]"
				}
				// The entry point evaluates startup before reading client input. Arm at
				// that read boundary to exercise the live kill gate, without a timer race.
				input := &denialActivationReader{Reader: strings.NewReader(request + "\n"), activate: func() { ks.SetAPI(true) }}
				var out, logs bytes.Buffer
				failed := &refusedReplyWriter{}
				var writer io.Writer = &out
				if strings.HasSuffix(disposition, "write_error") {
					writer = failed
				}
				ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(3*time.Second))
				defer cancel()
				var err error
				switch surface {
				case "http":
					upstream, calls := countingUpstream(t)
					err = RunHTTPProxy(ctx, input, writer, &logs, upstream.URL, nil, opts)
					if calls.Load() != 0 {
						t.Fatalf("kill refusal reached upstream: %d", calls.Load())
					}
				case "ws":
					upstream, frames := wsDrainServer(t)
					defer upstream.Close()
					err = RunWSProxy(ctx, input, writer, &logs, "ws"+strings.TrimPrefix(upstream.URL, "http"), opts)
					if frames.Load() != 0 {
						t.Fatalf("kill refusal reached upstream: %d", frames.Load())
					}
				case "stdio":
					var forwarded bytes.Buffer
					blocked := make(chan BlockedRequest, 1)
					ForwardScannedInput(transport.NewStdioReader(input), transport.NewStdioWriter(&forwarded), &logs, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
					if forwarded.Len() != 0 {
						t.Fatalf("kill refusal reached upstream: %s", forwarded.String())
					}
					for br := range blocked {
						err = deliverMCPInputResult(opts, br, transport.NewStdioWriter(writer))
					}
				}
				if surface == "stdio" && strings.HasSuffix(disposition, "write_error") {
					if !errors.Is(err, io.ErrClosedPipe) {
						t.Fatalf("delivery error=%v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				switch disposition {
				case "batch", "request":
					isBatch := strings.HasPrefix(strings.TrimSpace(out.String()), "[")
					if isBatch != (disposition == "batch") || !strings.Contains(out.String(), `"id":91`) || !strings.Contains(out.String(), `"code":-32004`) || strings.Contains(out.String(), `"result"`) {
						t.Fatalf("batch refusal=%s", out.String())
					}
				case "batch_write_error", "request_write_error":
					if failed.calls != 1 || (surface != "stdio" && !strings.Contains(logs.String(), "write error") && !strings.Contains(logs.String(), "failed to send kill switch response")) {
						t.Fatalf("writes=%d logs=%s", failed.calls, logs.String())
					}
				case "notification":
					if out.Len() != 0 {
						t.Fatalf("notification replied: %s", out.String())
					}
				}
				assertDenialRoute(t, events.String(), scanner.AuditKillSwitch, audit.BlockClassProtective, mcpResourceInput, "input")
			})
		}
	}
}
