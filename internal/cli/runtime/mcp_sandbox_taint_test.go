// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !mcp_hardening_test

package runtime

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const sandboxTaintHost = "bridge.vendor.example"

func TestMCPSandboxBridgeTaintRequiresRecorder(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  session.Recorder
	}{
		{name: "nil"},
		{name: "typed_nil", rec: (*proxy.SessionState)(nil)},
		{name: "adaptive_only", rec: sandboxAdaptiveOnlyRecorder{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cfg := config.Defaults()
			cfg.SessionProfiling.Enabled = false
			bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{Context: ctx, Config: cfg, Rec: tc.rec, AuditLogger: audit.NewNop()})
			if bridge != nil {
				bridge.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "taint") || !strings.Contains(err.Error(), "recorder") {
				t.Fatalf("taint-enabled bridge without recorder: error=%v, want explicit startup refusal", err)
			}
		})
	}
}

func TestMCPSandboxTaintAllocatesBeforeBridgeStartup(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("MCP sandbox egress bridge is Linux-only")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	invalidCert := filepath.Join(t.TempDir(), "invalid-ca.pem")
	invalidKey := filepath.Join(t.TempDir(), "invalid-key.pem")
	for _, file := range []string{invalidCert, invalidKey} {
		if err := os.WriteFile(file, []byte("invalid test PEM"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	body := fmt.Sprintf("session_profiling: {enabled: false}\ntaint: {enabled: true}\ntls_interception: {enabled: true, ca_cert: %q, ca_key: %q}\n", invalidCert, invalidKey)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, logs, err := runMCPProxyCommandWithInput(t, []string{"proxy", "--config", path, "--sandbox", "--", "/bin/echo", "ready"}, "")
	// Reach the configured CA refusal before any child launch. An absent
	// invocation recorder must instead fail the bridge's earlier taint guard.
	if err == nil || !strings.Contains(err.Error(), "MCP sandbox bridge TLS interception") || strings.Contains(err.Error(), "shared session risk recorder") {
		t.Fatalf("sandbox startup error=%v logs=%s", err, logs)
	}
}

func TestMCPStandaloneTaintWithoutProfiling(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					ID json.RawMessage `json:"id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":%q}]}}`, request.ID, "AKIA"+"IOSFODNN7EXAMPLE")
			}))
			t.Cleanup(upstream.Close)
			path := filepath.Join(t.TempDir(), "config.yaml")
			body := fmt.Sprintf("session_profiling: {enabled: false}\ntaint: {enabled: %t}\nresponse_scanning: {action: warn, mcp_servers: [{server: fixture, trust: reasoning}]}\n", enabled)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status","arguments":{}}}` + "\n" +
				`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/repo/auth/handler.go","content":"ready"}}}` + "\n"
			out, logs, err := runMCPProxyCommandWithInput(t, []string{"proxy", "--config", path, "--server-name", "fixture", "--upstream", upstream.URL}, input)
			if err != nil {
				t.Fatalf("standalone proxy: %v; logs=%s", err, logs)
			}
			wantCalls := int32(2)
			if enabled {
				wantCalls = 1
			}
			if calls.Load() != wantCalls || (enabled && !strings.Contains(out, "task_approval_unavailable")) {
				t.Fatalf("taint=%t calls=%d want=%d output=%s logs=%s", enabled, calls.Load(), wantCalls, out, logs)
			}
		})
	}
}

type sandboxAdaptiveOnlyRecorder struct{}

func (sandboxAdaptiveOnlyRecorder) RecordSignal(session.SignalType, float64) (bool, string, string) {
	return false, "", ""
}
func (sandboxAdaptiveOnlyRecorder) RecordClean(float64)  {}
func (sandboxAdaptiveOnlyRecorder) EscalationLevel() int { return 0 }
func (sandboxAdaptiveOnlyRecorder) ThreatScore() float64 { return 0 }

func TestMCPSandboxBridgeTaintDisabledNeedsNoRecorder(t *testing.T) {
	cfg := config.Defaults()
	cfg.Taint.Enabled = false
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{Context: ctx, Config: cfg, AuditLogger: audit.NewNop()})
	if err != nil {
		t.Fatal(err)
	}
	bridge.Close()
}

func TestMCPSandboxBridgeTaintInvalidCARefusesStartup(t *testing.T) {
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	cfg.TLSInterception.CACertPath = filepath.Join(t.TempDir(), "missing.pem")
	cfg.TLSInterception.CAKeyPath = filepath.Join(t.TempDir(), "missing-key.pem")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{Context: ctx, Config: cfg, Rec: &proxy.SessionState{}, AuditLogger: audit.NewNop()})
	if bridge != nil {
		bridge.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "TLS interception") {
		t.Fatalf("invalid CA error=%v", err)
	}
}

func TestMCPSandboxBridgeTaintStartupFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*config.Config, *mcpSandboxBridgeStartOptions)
		want      string
	}{
		{name: "receipt_cancellation", configure: func(cfg *config.Config, opts *mcpSandboxBridgeStartOptions) {
			cfg.FlightRecorder.RequireReceipts = true
			opts.ReceiptGroup = &mcp.MCPReceiptGroup{}
		}, want: "no cancellation callback"},
		{name: "scanner", configure: func(cfg *config.Config, _ *mcpSandboxBridgeStartOptions) {
			cfg.DLP.Patterns = []config.DLPPattern{{Name: "fixture", Regex: "[", Severity: config.SeverityHigh}}
		}, want: "scanner"},
		{name: "receipt_group", configure: func(_ *config.Config, opts *mcpSandboxBridgeStartOptions) {
			opts.ReceiptGroup = &mcp.MCPReceiptGroup{}
		}, want: "receipt group"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			opts := mcpSandboxBridgeStartOptions{Context: ctx, Config: cfg, Rec: &proxy.SessionState{}, AuditLogger: audit.NewNop()}
			tc.configure(cfg, &opts)
			bridge, err := startMCPSandboxBridge(opts)
			if bridge != nil {
				bridge.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("startup error=%v want=%s", err, tc.want)
			}
		})
	}
}

func sandboxTaintBridge(t *testing.T, cfg *config.Config, rec session.Recorder) *http.Client {
	t.Helper()
	cfg.Internal = nil // local fixtures only; host overrides prevent external DNS
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.TrustedDomains = []string{sandboxTaintHost}
	cfg.DNS.HostOverrides = map[string][]string{sandboxTaintHost: {"127.0.0.1"}}
	cfg.SessionProfiling.Enabled = false
	ca, key, _, err := certgen.GenerateCA("Sandbox bridge test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLSInterception.Enabled = true
	cfg.TLSInterception.CACertPath = filepath.Join(t.TempDir(), "ca.pem")
	cfg.TLSInterception.CAKeyPath = filepath.Join(t.TempDir(), "key.pem")
	if err := certgen.SaveCA(cfg.TLSInterception.CACertPath, cfg.TLSInterception.CAKeyPath, ca, key); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{
		Context: ctx, Cancel: cancel, Config: cfg, Rec: rec, AuditLogger: audit.NewNop(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridge.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	rt := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "bridge"}),
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", bridge.SocketPath())
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(rt.CloseIdleConnections)
	return &http.Client{Transport: rt, Timeout: 5 * time.Second}
}

func sandboxTaintTarget(t *testing.T, upstream string) string {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = net.JoinHostPort(sandboxTaintHost, u.Port())
	return u.String()
}

func sandboxMCPHostileResponse(t *testing.T, cfg *config.Config, rec session.Recorder) {
	t.Helper()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	// The documented example key is synthetic and constructed at runtime.
	response := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":%q}]}}`, "AKIA"+"IOSFODNN7EXAMPLE")
	_, err := mcp.ForwardScanned(transport.NewStdioReader(strings.NewReader(response+"\n")), transport.NewStdioWriter(io.Discard), io.Discard, nil,
		mcp.MCPProxyOpts{Scanner: sc, Rec: rec, TaintCfg: &cfg.Taint, TaintExternalSource: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.(session.RiskState).RiskSnapshot().Level; got != session.TaintExternalHostile {
		t.Fatalf("MCP response risk=%s, want hostile", got)
	}
}

func TestMCPSandboxBridgeTaintMCPToEgress(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = io.WriteString(w, "ready")
			}))
			if scheme == "https" {
				upstream.StartTLS()
			} else {
				upstream.Start()
			}
			t.Cleanup(upstream.Close)
			cfg := config.Defaults()
			cfg.ResponseScanning.Action = config.ActionWarn
			rec := &proxy.SessionState{}
			client := sandboxTaintBridge(t, cfg, rec)
			sandboxMCPHostileResponse(t, cfg, rec)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, sandboxTaintTarget(t, upstream.URL), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "task_approval_unavailable") || calls.Load() != 0 {
				t.Fatalf("%s POST status=%d upstream calls=%d body=%s", scheme, resp.StatusCode, calls.Load(), body)
			}
		})
	}
}

func TestMCPSandboxBridgeTaintEgressToMCP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "reference material")
	}))
	t.Cleanup(upstream.Close)
	cfg := config.Defaults()
	rec := &proxy.SessionState{}
	client := sandboxTaintBridge(t, cfg, rec)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, sandboxTaintTarget(t, upstream.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || rec.RiskSnapshot().Level != session.TaintExternalUntrusted {
		t.Fatalf("GET status=%d shared risk=%+v", resp.StatusCode, rec.RiskSnapshot())
	}
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	msg := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/repo/auth/handler.go","content":"ready"}}}`
	var sent bytes.Buffer
	blocked := make(chan mcp.BlockedRequest, 1)
	mcp.ForwardScannedInput(transport.NewStdioReader(strings.NewReader(msg+"\n")), transport.NewStdioWriter(&sent), io.Discard,
		config.ActionWarn, config.ActionBlock, blocked, nil, nil, mcp.MCPProxyOpts{Scanner: sc, Rec: rec, TaintCfg: &cfg.Taint})
	denial, ok := <-blocked
	if !ok || sent.Len() != 0 || !strings.Contains(denial.ErrorMessage, "protected_write_after_untrusted_external_exposure") {
		t.Fatalf("MCP after bridge exposure sent=%s denial=%+v", &sent, denial)
	}
}

func TestMCPSandboxBridgeTaintConcurrentResponseAndPublish(t *testing.T) {
	cfg := config.Defaults()
	cfg.ResponseScanning.Action = config.ActionWarn
	rec := &proxy.SessionState{}
	client := sandboxTaintBridge(t, cfg, rec)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ready")
	}))
	t.Cleanup(upstream.Close)
	target := sandboxTaintTarget(t, upstream.URL)
	// Seed the source so every publish must be refused, independent of which
	// of the concurrent operations is scheduled first.
	sandboxMCPHostileResponse(t, cfg, rec)
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	response := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":%q}]}}`, "AKIA"+"IOSFODNN7EXAMPLE")
	var wg sync.WaitGroup
	wg.Go(func() {
		_, err := mcp.ForwardScanned(transport.NewStdioReader(strings.NewReader(response+"\n")), transport.NewStdioWriter(io.Discard), io.Discard, nil,
			mcp.MCPProxyOpts{Scanner: sc, Rec: rec, TaintCfg: &cfg.Taint, TaintExternalSource: true})
		if err != nil {
			t.Error(err)
		}
	})
	wg.Go(func() {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, nil)
		if err != nil {
			t.Error(err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("concurrent POST status=%d", resp.StatusCode)
		}
	})
	wg.Wait()
}
