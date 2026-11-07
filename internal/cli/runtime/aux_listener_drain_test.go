// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// Both auxiliary receipt listeners must carry their drain result all the way
// through Start's deferred seal, including clean-drain positive controls.
func TestServer_AuxiliaryListenerDrainSeal(t *testing.T) {
	for _, listener := range []string{"reverse proxy", "MCP"} {
		for _, incomplete := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/incomplete=%t", listener, incomplete), func(t *testing.T) {
				upstream, entered, release := heldDrainUpstream(t)
				dir, cfgPath := drainReceiptConfig(t, 1)
				s, log := newTestServerForStart(t, func(o *ServerOpts) {
					o.ConfigFile = cfgPath
					o.Listen = serverTestEphemeralListen
					o.ListenChanged = true
					o.listenerShutdownTimeout = drainTestTimeout(incomplete)
					if listener == "MCP" {
						o.MCPListen = serverTestEphemeralListen
						o.MCPUpstream = upstream
					} else {
						o.ReverseProxy = true
						o.ReverseListen = serverTestEphemeralListen
						o.ReverseUpstream = upstream
					}
				})
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := startDrainLifecycle(t, cancel, release, func() error { return s.Start(ctx) })
				prefix := "pipelock: reverse proxy listening on "
				if listener == "MCP" {
					prefix = "pipelock: MCP reverse proxy listening on "
				}
				address := drainListenerAddress(t, log, prefix)
				requestDone := startDrainRequest(t, address, listener == "MCP")
				awaitDrainSignal(t, entered, "upstream request")
				cancel()
				if !incomplete {
					waitDrainListenerClosed(t, address)
					release()
				}
				err := awaitDrainResult(t, done)
				assertDrainResult(t, err, incomplete, listener)
				awaitDrainRequest(t, requestDone, incomplete)
				release()
				assertDrainEvidence(t, dir, incomplete, false)
			})
		}
	}
}

func TestMCPProxyCmd_ListenerDrainSeal(t *testing.T) {
	for _, chains := range []int{1, 2} {
		for _, incomplete := range []bool{true, false} {
			t.Run(fmt.Sprintf("chains=%d/incomplete=%t", chains, incomplete), func(t *testing.T) {
				upstream, entered, release := heldDrainUpstream(t)
				dir, cfgPath := drainReceiptConfig(t, chains)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				cmd := mcpProxyCmdWithListenerTimeout(audit.NewWithStream, drainTestTimeout(incomplete))
				cmd.SetContext(ctx)
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				log := &syncBuffer{}
				cmd.SetOut(io.Discard)
				cmd.SetErr(log)
				cmd.SetIn(strings.NewReader(""))
				cmd.SetArgs([]string{"--config", cfgPath, "--listen", serverTestEphemeralListen, "--upstream", upstream})
				done := startDrainLifecycle(t, cancel, release, cmd.Execute)
				address := drainListenerAddress(t, log, "pipelock: MCP reverse proxy listening on ")
				requestDone := startDrainRequest(t, address, true)
				awaitDrainSignal(t, entered, "upstream request")
				cancel()
				if !incomplete {
					waitDrainListenerClosed(t, address)
					release()
				}
				err := awaitDrainResult(t, done)
				assertDrainResult(t, err, incomplete, "MCP HTTP listener")
				awaitDrainRequest(t, requestDone, incomplete)
				release()
				assertDrainEvidence(t, dir, incomplete, chains > 1)
			})
		}
	}
}

func drainTestTimeout(incomplete bool) time.Duration {
	if incomplete {
		return 25 * time.Millisecond
	}
	return 5 * time.Second
}

func heldDrainUpstream(t *testing.T) (string, <-chan struct{}, func()) {
	t.Helper()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"test","version":"1.0"}}}`)
		} else {
			_, _ = io.WriteString(w, "finished")
		}
	}))
	// Release before httptest.Close waits for any outstanding upstream request.
	t.Cleanup(upstream.Close)
	t.Cleanup(unblock)
	return upstream.URL, entered, unblock
}

func drainReceiptConfig(t *testing.T, chains int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatal(err)
	}
	return dir, writeServerTestConfig(t, fmt.Sprintf("mode: balanced\nflight_recorder:\n  enabled: true\n  dir: %s\n  signing_key_path: %s\n  sign_checkpoints: true\n  receipt_chains: %d\n", strconv.Quote(dir), strconv.Quote(keyPath), chains))
}

func drainListenerAddress(t *testing.T, log *syncBuffer, prefix string) string {
	t.Helper()
	var address string
	testwait.For(t, 10*time.Second, func() bool {
		_, after, ok := strings.Cut(log.String(), prefix)
		if ok {
			address = strings.Fields(after)[0]
		}
		return address != ""
	}, "receipt listener startup: %s", prefix)
	return address
}

func startDrainRequest(t *testing.T, address string, mcp bool) <-chan error {
	t.Helper()
	method := http.MethodGet
	var body io.Reader
	if mcp {
		method = http.MethodPost
		body = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, "http://"+address+"/", body)
	if err != nil {
		t.Fatal(err)
	}
	if mcp {
		req.Header.Set("Content-Type", "application/json")
	}
	done := make(chan error, 1)
	go func() {
		// The test deadline bounds this wait; a client timeout must not
		// masquerade as the proxy force-closing the connection.
		client := &http.Client{}
		resp, requestErr := client.Do(req)
		if requestErr == nil {
			_, requestErr = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				requestErr = fmt.Errorf("HTTP status %d", resp.StatusCode)
			}
		}
		done <- requestErr
	}()
	return done
}

func awaitDrainSignal(t *testing.T, signal <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(testwait.Deadline(10 * time.Second)):
		t.Fatal("timed out waiting for " + what)
	}
}

func awaitDrainResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(testwait.Deadline(10 * time.Second)):
		t.Fatal("listener lifecycle did not return")
		return nil
	}
}

func assertDrainResult(t *testing.T, err error, incomplete bool, listener string) {
	t.Helper()
	if incomplete {
		if !errors.Is(err, proxy.ErrShutdownIncomplete) || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("listener result = %v, want ErrShutdownIncomplete and DeadlineExceeded", err)
		}
		if err == nil || !strings.Contains(err.Error(), listener) {
			t.Errorf("listener result = %v, want listener name %q", err, listener)
		}
	} else if err != nil {
		t.Errorf("clean drain = %v", err)
	}
}

func assertDrainEvidence(t *testing.T, dir string, incomplete, group bool) {
	t.Helper()
	// session_open is the known positive: an empty evidence directory must not
	// make the absence checks pass.
	if !evidenceDirContains(t, dir, "session_open") {
		t.Fatal("missing session_open evidence")
	}
	for _, marker := range []string{"transcript_root", "session_close"} {
		if got := evidenceDirContains(t, dir, marker); got == incomplete {
			t.Errorf("%s present = %t, want %t", marker, got, !incomplete)
		}
	}
	if group {
		// Group manifests are stored below the recorder directory.
		matches, err := filepath.Glob(filepath.Join(dir, "receipt-group-*-close.json"))
		if err != nil {
			t.Fatal(err)
		}
		if got := len(matches) > 0; got == incomplete {
			t.Errorf("group close present = %t, want %t (paths %v)", got, !incomplete, matches)
		}
	}
}

func awaitDrainRequest(t *testing.T, done <-chan error, incomplete bool) {
	t.Helper()
	select {
	case err := <-done:
		if !incomplete && err != nil {
			t.Fatalf("clean request failed: %v", err)
		}
	case <-time.After(testwait.Deadline(10 * time.Second)):
		t.Fatal("downstream request did not close after listener stopped")
	}
}

func waitDrainListenerClosed(t *testing.T, address string) {
	t.Helper()
	testwait.For(t, 5*time.Second, func() bool {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(t.Context(), "tcp", address)
		if err != nil {
			return true
		}
		_ = conn.Close()
		return false
	}, "listener to close before releasing in-flight handler")
}

func startDrainLifecycle(t *testing.T, cancel context.CancelFunc, release func(), run func() error) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- run()
	}()
	// Release the controlled handler and join Start before earlier test cleanups
	// restore configuration. Start owns server resource cleanup.
	t.Cleanup(func() {
		release()
		cancel()
		awaitDrainSignal(t, finished, "listener lifecycle teardown")
	})
	return done
}

// Unread and half-sent sockets have reached no receipt producer. Exercise both
// on each runtime auxiliary listener and prove that the run still seals.
func TestServer_AuxiliaryUnreadConnectionsSeal(t *testing.T) {
	for _, listener := range []string{"reverse proxy", "MCP", "scan API"} {
		t.Run(listener, func(t *testing.T) {
			dir, cfgPath := drainReceiptConfig(t, 1)
			s, log := newTestServerForStart(t, func(o *ServerOpts) {
				o.ConfigFile = cfgPath
				o.Listen = serverTestEphemeralListen
				o.ListenChanged = true
				o.listenerShutdownTimeout = 50 * time.Millisecond
				if listener == "MCP" {
					o.MCPListen = serverTestEphemeralListen
					o.MCPUpstream = serverTestUpstreamURL
				}
				if listener == "reverse proxy" {
					o.ReverseProxy = true
					o.ReverseListen = serverTestEphemeralListen
					o.ReverseUpstream = serverTestUpstreamURL
				}
			})
			prefix := "pipelock: reverse proxy listening on "
			if listener == "MCP" {
				prefix = "pipelock: MCP reverse proxy listening on "
			}
			if listener == "scan API" {
				s.cfg.ScanAPI.Listen = serverTestEphemeralListen
				prefix = "pipelock: scan API listening on "
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := startDrainLifecycle(t, cancel, func() {}, func() error { return s.Start(ctx) })
			address := drainListenerAddress(t, log, prefix)
			unreadDrainSockets(t, address)
			cancel()
			if err := awaitDrainResult(t, done); err != nil {
				t.Fatalf("unread sockets made drain incomplete: %v", err)
			}
			assertDrainEvidence(t, dir, false, false)
		})
	}
}

func TestMCPProxyCmd_UnreadConnectionsSeal(t *testing.T) {
	for _, chains := range []int{1, 2} {
		t.Run(fmt.Sprintf("chains=%d", chains), func(t *testing.T) {
			dir, cfgPath := drainReceiptConfig(t, chains)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cmd := mcpProxyCmdWithListenerTimeout(audit.NewWithStream, 50*time.Millisecond)
			cmd.SetContext(ctx)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			log := &syncBuffer{}
			cmd.SetErr(log)
			cmd.SetOut(io.Discard)
			cmd.SetIn(strings.NewReader(""))
			cmd.SetArgs([]string{"--config", cfgPath, "--listen", serverTestEphemeralListen, "--upstream", serverTestUpstreamURL})
			done := startDrainLifecycle(t, cancel, func() {}, cmd.Execute)
			address := drainListenerAddress(t, log, "pipelock: MCP reverse proxy listening on ")
			unreadDrainSockets(t, address)
			cancel()
			if err := awaitDrainResult(t, done); err != nil {
				t.Fatalf("unread sockets made drain incomplete: %v", err)
			}
			assertDrainEvidence(t, dir, false, chains > 1)
		})
	}
}

func unreadDrainSockets(t *testing.T, address string) {
	t.Helper()
	for _, send := range []string{"", "GET / HTTP/1.1\r\nHost: x\r\n"} {
		conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if send != "" {
			if _, err := io.WriteString(conn, send); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A later request proves Serve accepted the earlier sockets. This request is
	// deliberately unauthenticated; any HTTP response suffices for this barrier.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+address+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

// Hold the real shared scanner warning hook, after it emits a signed warning,
// so Scan API work survives cancellation without relying on slow input or DNS.
func TestServer_ScanAPIDrainSeal(t *testing.T) {
	for _, incomplete := range []bool{true, false} {
		t.Run(fmt.Sprintf("incomplete=%t", incomplete), func(t *testing.T) {
			dir, cfgPath := drainReceiptConfig(t, 1)
			data, err := os.ReadFile(filepath.Clean(cfgPath))
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, []byte("dlp:\n  patterns:\n    - name: drain-warning-probe\n      regex: drain-warning-probe\n      severity: low\n      action: warn\n")...)
			if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			s, log := newTestServerForStart(t, func(o *ServerOpts) {
				o.ConfigFile = cfgPath
				o.Listen = serverTestEphemeralListen
				o.ListenChanged = true
				o.listenerShutdownTimeout = drainTestTimeout(incomplete)
			})
			s.cfg.ScanAPI.Listen = serverTestEphemeralListen
			s.cfg.ScanAPI.Auth.BearerTokens = []string{"test-" + "scan-token"}
			entered, released, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(released) }) }
			s.proxy.ScannerPtr().Load().SetDLPWarnHook(func(ctx context.Context, pattern, severity string) {
				emitDLPWarn(s.logger, s.metrics, s.liveReceiptEmitter(), ctx, pattern, severity)
				close(entered)
				<-released
				close(finished)
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := startDrainLifecycle(t, cancel, release, func() error { return s.Start(ctx) })
			address := drainListenerAddress(t, log, "pipelock: scan API listening on ")
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+address+"/api/v1/scan", strings.NewReader(`{"kind":"dlp","input":{"text":"drain-warning-probe"}}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+s.cfg.ScanAPI.Auth.BearerTokens[0])
			requestDone := make(chan error, 1)
			go func() {
				resp, err := (&http.Client{}).Do(req)
				if err == nil {
					_, err = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						err = fmt.Errorf("scan API status %d", resp.StatusCode)
					}
				}
				requestDone <- err
			}()
			awaitDrainSignal(t, entered, "Scan API warning hook")
			cancel()
			if !incomplete {
				waitDrainListenerClosed(t, address)
				release()
			}
			err = awaitDrainResult(t, done)
			assertDrainResult(t, err, incomplete, "scan API listener")
			awaitDrainRequest(t, requestDone, incomplete)
			release()
			awaitDrainSignal(t, finished, "Scan API hook completion")
			assertSignedDrainWarning(t, dir, s.cfg.FlightRecorder.SigningKeyPath)
			assertDrainEvidence(t, dir, incomplete, false)
		})
	}
}

func TestServer_ReverseSSEPendingScanLeavesRunUnsealed(t *testing.T) {
	// The scan is held deliberately. Keep the scanner's separate 30-second
	// cleanup grace short using its existing nonparallel-test hook.
	defer scanner.SetCloseDrainTimeoutForTest(50 * time.Millisecond)()
	dir, cfgPath := drainReceiptConfig(t, 1)
	data, err := os.ReadFile(filepath.Clean(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("dlp:\n  patterns:\n    - name: drain-warning-probe\n      regex: drain-warning-probe\n      severity: low\n      action: warn\nresponse_scanning:\n  enabled: true\n  action: warn\n  sse_streaming:\n    enabled: true\n    action: warn\n")...)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: drain-warning-probe\n\n")
	}))
	defer upstream.Close()
	s, log := newTestServerForStart(t, func(o *ServerOpts) {
		o.ConfigFile = cfgPath
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
		o.ReverseProxy = true
		o.ReverseListen = serverTestEphemeralListen
		o.ReverseUpstream = upstream.URL
		o.listenerShutdownTimeout = 50 * time.Millisecond
	})
	entered, released, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once, warningOnce sync.Once
	release := func() { once.Do(func() { close(released) }) }
	s.proxy.ScannerPtr().Load().SetDLPWarnHook(func(ctx context.Context, pattern, severity string) {
		warningOnce.Do(func() {
			defer close(finished)
			emitDLPWarn(s.logger, s.metrics, s.liveReceiptEmitter(), ctx, pattern, severity)
			close(entered)
			<-released
		})
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := startDrainLifecycle(t, cancel, release, func() error { return s.Start(ctx) })
	address := drainListenerAddress(t, log, "pipelock: reverse proxy listening on ")
	clientCtx, disconnect := context.WithCancel(t.Context())
	defer disconnect()
	req, err := http.NewRequestWithContext(clientCtx, http.MethodGet, "http://"+address+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() {
		resp, err := (&http.Client{}).Do(req)
		if err == nil {
			_, err = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		requestDone <- err
	}()
	awaitDrainSignal(t, entered, "reverse SSE warning scan")
	disconnect()
	awaitDrainRequest(t, requestDone, true)
	cancel()
	err = awaitDrainResult(t, done)
	assertDrainResult(t, err, true, "reverse proxy listener")
	release()
	awaitDrainSignal(t, finished, "reverse SSE warning hook completion")
	assertSignedDrainWarning(t, dir, s.cfg.FlightRecorder.SigningKeyPath)
	assertDrainEvidence(t, dir, true, false)
}

func TestServer_MainAgentUnreadConnectionsSeal(t *testing.T) {
	dir, cfgPath := drainReceiptConfig(t, 1)
	s, log := newTestServerForStart(t, func(o *ServerOpts) {
		o.ConfigFile = cfgPath
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})
	agentLn, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", serverTestEphemeralListen)
	if err != nil {
		t.Fatal(err)
	}
	agent := newHTTPServer(http.NotFoundHandler())
	s.proxy.RegisterAgentServer(agent)
	t.Cleanup(func() { _ = agent.Close() })
	go func() { _ = agent.Serve(agentLn) }()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := startDrainLifecycle(t, cancel, func() {}, func() error { return s.Start(ctx) })
	mainAddr := drainListenerAddress(t, log, "  Listen: ")
	for _, addr := range []string{mainAddr, agentLn.Addr().String()} {
		unreadDrainSockets(t, addr)
	}
	cancel()
	if err := awaitDrainResult(t, done); err != nil {
		t.Fatalf("unread main/agent drain = %v", err)
	}
	assertDrainEvidence(t, dir, false, false)
}

func assertSignedDrainWarning(t *testing.T, dir, keyPath string) {
	t.Helper()
	key, err := signing.LoadPrivateKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		entries, err := recorder.ReadEntries(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Type != "action_receipt" {
				continue
			}
			var rcpt receipt.Receipt
			if err := json.Unmarshal(entry.RawDetail, &rcpt); err != nil {
				t.Fatal(err)
			}
			if rcpt.ActionRecord.Pattern != "drain-warning-probe" {
				continue
			}
			if err := receipt.VerifyWithKey(rcpt, pub); err != nil {
				t.Fatalf("warning receipt signature: %v", err)
			}
			t.Logf("signature-verified warning receipt: verdict=%s", rcpt.ActionRecord.Verdict)
			return
		}
	}
	t.Fatal("missing signed drain warning receipt")
}
