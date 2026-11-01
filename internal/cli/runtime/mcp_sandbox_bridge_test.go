// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !mcp_hardening_test

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
)

func TestMCPSandboxBridgeRequiredGroupNeedsCancellation(t *testing.T) {
	group := &mcp.MCPReceiptGroup{}
	_, err := bridgeRequiredReceiptFailure(group, true, nil)
	if err == nil || !strings.Contains(err.Error(), "no cancellation callback") {
		t.Fatalf("required receipt group without cancellation = %v", err)
	}
	called := false
	callback, err := bridgeRequiredReceiptFailure(group, true, func() { called = true })
	if err != nil || callback == nil {
		t.Fatalf("required receipt group callback present = %t, error = %v", callback != nil, err)
	}
	callback(errors.New("receipt persistence failed"))
	if !called {
		t.Fatal("required receipt failure did not cancel the bridge parent")
	}
	callback, err = bridgeRequiredReceiptFailure(group, false, nil)
	if err != nil || callback != nil {
		t.Fatalf("best-effort receipt group callback present = %t, error = %v", callback != nil, err)
	}
}

func TestSetupMCPSandboxBridge_LinuxStartsBridge(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	ks := killswitch.New(cfg)
	var stderr bytes.Buffer
	launchCfg := sandbox.LaunchConfig{}
	started := false

	closeBridge, err := setupMCPSandboxBridge(
		mcpSandboxBridgeSetupOptions{
			Context:          context.Background(),
			GOOS:             "linux",
			Config:           cfg,
			KillSwitch:       ks,
			MetricsBoundAddr: "127.0.0.2:9091",
			AuditLogger:      audit.NewNop(),
			Stderr:           &stderr,
			LaunchConfig:     &launchCfg,
			StartBridge: func(opts mcpSandboxBridgeStartOptions) (*mcpSandboxBridge, error) {
				if opts.Config != cfg || opts.KillSwitch != ks || opts.MetricsBoundAddr != "127.0.0.2:9091" {
					t.Fatal("bridge start options did not preserve config and kill switch")
				}
				started = true
				return &mcpSandboxBridge{socketPath: "/tmp/pl-mcp-test/proxy.sock"}, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("setupMCPSandboxBridge: %v", err)
	}
	if !started {
		t.Fatal("bridge starter was not called")
	}
	if launchCfg.BridgeSocketPath != "/tmp/pl-mcp-test/proxy.sock" {
		t.Fatalf("BridgeSocketPath = %q", launchCfg.BridgeSocketPath)
	}
	if got := stderr.String(); !strings.Contains(got, "MCP sandbox egress bridge enabled") {
		t.Fatalf("stderr = %q, want bridge enabled message", got)
	}
	closeBridge()
}

func TestSetupMCPSandboxBridge_StartError(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	wantErr := errors.New("bridge unavailable")
	launchCfg := sandbox.LaunchConfig{}

	closeBridge, err := setupMCPSandboxBridge(
		mcpSandboxBridgeSetupOptions{
			Context:      context.Background(),
			GOOS:         "linux",
			Config:       cfg,
			KillSwitch:   killswitch.New(cfg),
			AuditLogger:  audit.NewNop(),
			Stderr:       io.Discard,
			LaunchConfig: &launchCfg,
			StartBridge: func(mcpSandboxBridgeStartOptions) (*mcpSandboxBridge, error) {
				return nil, wantErr
			},
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if closeBridge != nil {
		t.Fatal("closeBridge should be nil on start error")
	}
	if launchCfg.BridgeSocketPath != "" {
		t.Fatalf("BridgeSocketPath = %q, want empty", launchCfg.BridgeSocketPath)
	}
}

func TestSetupMCPSandboxBridge_NonLinuxWarns(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	var stderr bytes.Buffer
	launchCfg := sandbox.LaunchConfig{}
	started := false

	closeBridge, err := setupMCPSandboxBridge(
		mcpSandboxBridgeSetupOptions{
			Context:      context.Background(),
			GOOS:         "darwin",
			Config:       cfg,
			KillSwitch:   killswitch.New(cfg),
			AuditLogger:  audit.NewNop(),
			Stderr:       &stderr,
			LaunchConfig: &launchCfg,
			StartBridge: func(mcpSandboxBridgeStartOptions) (*mcpSandboxBridge, error) {
				started = true
				return nil, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("setupMCPSandboxBridge: %v", err)
	}
	if started {
		t.Fatal("bridge starter should not run on non-Linux")
	}
	if launchCfg.BridgeSocketPath != "" {
		t.Fatalf("BridgeSocketPath = %q, want empty", launchCfg.BridgeSocketPath)
	}
	got := stderr.String()
	if !strings.Contains(got, "Linux-only") || !strings.Contains(got, "HTTPS_PROXY") {
		t.Fatalf("stderr = %q, want actionable non-Linux warning", got)
	}
	closeBridge()
}

func TestMCPSandboxBridgeHelpers_NilAndClosed(t *testing.T) {
	t.Parallel()

	var nilBridge *mcpSandboxBridge
	if nilBridge.SocketPath() != "" {
		t.Fatal("nil bridge SocketPath should be empty")
	}
	nilBridge.Close()

	trackedConn, peerConn := net.Pipe()
	t.Cleanup(func() { _ = peerConn.Close() })

	bridge := &mcpSandboxBridge{
		conns: map[net.Conn]struct{}{
			trackedConn: {},
		},
	}
	conns := bridge.markClosed()
	if len(conns) != 1 || conns[0] != trackedConn {
		t.Fatalf("markClosed tracked %d conn(s), want original tracked conn", len(conns))
	}
	if bridge.trackConn(peerConn) {
		t.Fatal("trackConn succeeded after bridge was marked closed")
	}
	bridge.Close()
}

func TestStartMCPSandboxBridge_ForcesForwardProxyIntoScanner(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "bridge-ok")
	}))
	t.Cleanup(upstream.Close)

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.ForwardProxy.Enabled = false

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{
		Context:     ctx,
		Config:      cfg,
		KillSwitch:  killswitch.New(cfg),
		AuditLogger: audit.NewNop(),
	})
	if err != nil {
		t.Fatalf("startMCPSandboxBridge: %v", err)
	}
	t.Cleanup(bridge.Close)

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", bridge.SocketPath())
	if err != nil {
		t.Fatalf("dial bridge socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: ignored.invalid\r\nConnection: close\r\n\r\n", upstream.URL)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want scanner block 403; body=%q", resp.StatusCode, string(body))
	}
	if got := string(body); !strings.Contains(got, "SSRF") {
		t.Fatalf("body = %q, want scanner SSRF block", got)
	}
	if cfg.ForwardProxy.Enabled {
		t.Fatal("startMCPSandboxBridge mutated caller config")
	}
}

func TestStartMCPSandboxBridge_CONNECTThroughScanner(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	targetLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })

	go func() {
		conn, acceptErr := targetLn.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, buf); readErr != nil {
			return
		}
		_, _ = conn.Write([]byte("pong"))
	}()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.ForwardProxy.Enabled = false

	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{
		Context:     ctx,
		Config:      cfg,
		KillSwitch:  killswitch.New(cfg),
		AuditLogger: audit.NewNop(),
	})
	if err != nil {
		t.Fatalf("startMCPSandboxBridge: %v", err)
	}
	t.Cleanup(bridge.Close)

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", bridge.SocketPath())
	if err != nil {
		t.Fatalf("dial bridge socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	target := targetLn.Addr().String()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("CONNECT status = %d, want 200; body=%q", resp.StatusCode, string(body))
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read tunnel payload: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("tunnel echo = %q, want pong", string(got))
	}
}

func TestStartMCPSandboxBridge_ContextCancelClosesTunnel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targetLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })

	targetSeen := make(chan struct{})
	go func() {
		conn, acceptErr := targetLn.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, buf); readErr == nil {
			close(targetSeen)
		}
		_, _ = io.Copy(io.Discard, conn)
	}()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.ForwardProxy.Enabled = false

	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{
		Context:     ctx,
		Config:      cfg,
		KillSwitch:  killswitch.New(cfg),
		AuditLogger: audit.NewNop(),
	})
	if err != nil {
		t.Fatalf("startMCPSandboxBridge: %v", err)
	}
	t.Cleanup(bridge.Close)

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", bridge.SocketPath())
	if err != nil {
		t.Fatalf("dial bridge socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	target := targetLn.Addr().String()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("CONNECT status = %d, want 200; body=%q", resp.StatusCode, string(body))
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}
	select {
	case <-targetSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("target did not receive tunnel payload before cancel")
	}

	cancel()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if n, err := br.Read(buf); err == nil {
		t.Fatalf("read after cancel succeeded with %d byte(s), want closed tunnel", n)
	}
}

func TestStartMCPSandboxBridge_KillSwitchBlocks(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.Message = "bridge denied"
	cfg.ForwardProxy.Enabled = false

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{
		Context:     ctx,
		Config:      cfg,
		KillSwitch:  killswitch.New(cfg),
		AuditLogger: audit.NewNop(),
	})
	if err != nil {
		t.Fatalf("startMCPSandboxBridge: %v", err)
	}
	t.Cleanup(bridge.Close)

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", bridge.SocketPath())
	if err != nil {
		t.Fatalf("dial bridge socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprint(conn, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", resp.StatusCode, string(body))
	}
	if got := string(body); !strings.Contains(got, "kill_switch_active") {
		t.Fatalf("body = %q, want kill_switch_active", got)
	}
}

func TestMCPSandboxBridgeNeverServesMetrics(t *testing.T) {
	for _, address := range []string{"", "127.0.0.1:9091"} {
		for _, active := range []bool{false, true} {
			t.Run(fmt.Sprintf("address=%s/kill=%t", address, active), func(t *testing.T) {
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.MetricsListen = address
				cfg.KillSwitch.Enabled = active
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{
					Context: ctx, Config: cfg, KillSwitch: killswitch.New(cfg), AuditLogger: audit.NewNop(),
				})
				if err != nil {
					t.Fatal(err)
				}
				defer bridge.Close()
				for _, route := range []string{"/health", "/metrics", "/stats"} {
					conn, err := (&net.Dialer{}).DialContext(ctx, "unix", bridge.SocketPath())
					if err != nil {
						t.Fatal(err)
					}
					if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: proxy.example\r\nConnection: close\r\n\r\n", route); err != nil {
						t.Fatal(err)
					}
					resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
					if err != nil {
						_ = conn.Close()
						t.Fatal(err)
					}
					_ = resp.Body.Close()
					_ = conn.Close()
					want := http.StatusNotFound
					if route == "/health" {
						want = http.StatusOK
					}
					if route == "/stats" && active {
						want = http.StatusServiceUnavailable
					}
					if resp.StatusCode != want {
						t.Fatalf("bridge %s = %d, want %d", route, resp.StatusCode, want)
					}
				}
			})
		}
	}
}

func TestMCPSandboxBridgeMetricsUsesBoundAddress(t *testing.T) {
	// The configured target represents an earlier resolution. The listener's
	// numeric address must win even when that snapshot names another local IP.
	var output bytes.Buffer
	stop, boundAddr, err := startDedicatedMetricsServer(t.Context(), "127.0.0.2:0", metrics.New(), &output)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	_, port, err := net.SplitHostPort(boundAddr)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.MetricsListen = net.JoinHostPort("127.0.0.1", port)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{
		Context: ctx, Config: cfg, KillSwitch: killswitch.New(cfg), AuditLogger: audit.NewNop(), MetricsBoundAddr: boundAddr,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", bridge.SocketPath())
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, route := range []string{"/metrics", "/stats"} {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, "http://bridge/fetch?url=http://"+boundAddr+route, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			t.Fatal(doErr)
		}
		data, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusForbidden || !bytes.Contains(data, []byte("ssrf_private_ip")) {
			t.Fatalf("agent metrics dial %s = %d, %v, %s", route, resp.StatusCode, readErr, data)
		}
	}
}
