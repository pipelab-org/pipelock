// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
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
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testport"
)

// doReq is a test helper that creates and executes an HTTP request with context.
func doReq(t *testing.T, client *http.Client, method, url string, body string, headers map[string]string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// TestKillSwitchPortIsolation_APIOnSeparatePort verifies that when
// api_listen is configured, the main proxy port does NOT register API
// routes (returns 404) and the separate API port serves them normally.
func TestKillSwitchPortIsolation_APIOnSeparatePort(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF for tests
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.ApplyDefaults()

	// Allocate a free port for the API server.
	apiLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind API listener: %v", err)
	}
	apiAddr := apiLn.Addr().String()
	cfg.KillSwitch.APIListen = apiAddr
	cfg.KillSwitch.APIToken = "test-token-integration" //nolint:gosec // test value

	logger, _ := audit.New("json", "stdout", "", false, false)
	defer logger.Close()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	m := metrics.New()

	ks := killswitch.New(cfg)
	ks.SetSeparateAPIPort(true)
	ksAPI := killswitch.NewAPIHandler(ks)

	// Build proxy WITHOUT kill switch API routes (simulates api_listen set).
	p, err := New(cfg, logger, sc, m, WithKillSwitch(ks))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	// Start the main proxy on a free port.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind proxy listener: %v", err)
	}
	proxyAddr := proxyLn.Addr().String()

	// Override the config listen address to match.
	cfg.FetchProxy.Listen = proxyAddr

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.HandleFunc("/health", p.handleHealth)
	mux.Handle("/metrics", m.PrometheusHandler())
	// Intentionally NOT registering /api/v1/* routes here.
	proxySrv := &http.Server{
		Handler:           p.buildHandler(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { _ = proxySrv.Serve(proxyLn) }()
	defer func() { _ = proxySrv.Shutdown(context.Background()) }()

	// Start the separate API server.
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/v1/killswitch", ksAPI.HandleToggle)
	apiMux.HandleFunc("/api/v1/killswitch/status", ksAPI.HandleStatus)
	apiSrv := &http.Server{
		Handler:           apiMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { _ = apiSrv.Serve(apiLn) }()
	defer func() { _ = apiSrv.Shutdown(context.Background()) }()

	client := &http.Client{Timeout: 5 * time.Second}
	authHeader := map[string]string{"Authorization": "Bearer test-token-integration"} //nolint:gosec // test value

	// 1. Main port: /api/v1/killswitch should return 404 (not registered).
	resp := doReq(t, client, http.MethodPost,
		fmt.Sprintf("http://%s/api/v1/killswitch", proxyAddr),
		`{"active": true}`, nil)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 on main port for /api/v1/killswitch, got %d", resp.StatusCode)
	}

	// 2. API port: activate kill switch via proper auth.
	resp = doReq(t, client, http.MethodPost,
		fmt.Sprintf("http://%s/api/v1/killswitch", apiAddr),
		`{"active": true}`, authHeader)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on API port activation, got %d", resp.StatusCode)
	}

	// 2b. Main port: /fetch should be denied (503) - core security property.
	resp = doReq(t, client, http.MethodGet,
		fmt.Sprintf("http://%s/fetch?url=http://example.com", proxyAddr), "", nil)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 on main port /fetch when kill switch active, got %d", resp.StatusCode)
	}

	// 3. Main port: /health should still work (exempt) and report kill switch active.
	resp = doReq(t, client, http.MethodGet,
		fmt.Sprintf("http://%s/health", proxyAddr), "", nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /health, got %d", resp.StatusCode)
	}
	var health healthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("unmarshal /health: %v", err)
	}
	if !health.KillSwitchActive {
		t.Error("expected kill_switch_active=true in /health response after activation")
	}

	// 4. API port: status should show api source active.
	resp = doReq(t, client, http.MethodGet,
		fmt.Sprintf("http://%s/api/v1/killswitch/status", apiAddr),
		"", authHeader)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on API status, got %d", resp.StatusCode)
	}
	var status struct {
		Active  bool            `json:"active"`
		Sources map[string]bool `json:"sources"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if !status.Active {
		t.Error("expected active=true in status response")
	}
	if !status.Sources["api"] {
		t.Error("expected sources.api=true in status response")
	}

	// 5. Deactivate via API port.
	resp = doReq(t, client, http.MethodPost,
		fmt.Sprintf("http://%s/api/v1/killswitch", apiAddr),
		`{"active": false}`, authHeader)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on deactivation, got %d", resp.StatusCode)
	}

	// 6. Health should now show kill switch inactive.
	resp = doReq(t, client, http.MethodGet,
		fmt.Sprintf("http://%s/health", proxyAddr), "", nil)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck,gosec // test
	var health2 healthResponse
	if err := json.Unmarshal(body, &health2); err != nil {
		t.Fatalf("unmarshal /health: %v", err)
	}
	if health2.KillSwitchActive {
		t.Error("expected kill_switch_active=false in /health response after deactivation")
	}
}

// TestKillSwitchPortIsolation_DefaultBehavior verifies that when
// api_listen is empty (default), the API routes are registered on the
// main proxy port as before.
func TestKillSwitchPortIsolation_DefaultBehavior(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		return exerciseKillSwitchOnProxyPort(t, addrs[0])
	})
}

// exerciseKillSwitchOnProxyPort starts the proxy on addr and checks the API
// route. Start's bind error is returned so a stolen port is retried.
func exerciseKillSwitchOnProxyPort(t *testing.T, addr string) error {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.ApplyDefaults()
	cfg.KillSwitch.APIToken = "test-token-default" //nolint:gosec // test value

	logger, loggerErr := audit.New("json", "stdout", "", false, false)
	if loggerErr != nil {
		return fmt.Errorf("audit logger: %w", loggerErr)
	}
	defer logger.Close()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	m := metrics.New()

	ks := killswitch.New(cfg)
	ksAPI := killswitch.NewAPIHandler(ks)

	// Build proxy WITH kill switch API routes (default behavior).
	p, err := New(cfg, logger, sc, m, WithKillSwitch(ks), WithKillSwitchAPI(ksAPI))
	if err != nil {
		return fmt.Errorf("proxy.New: %w", err)
	}

	// Start reads the listen address from this config pointer.
	cfg.FetchProxy.Listen = addr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startErr := make(chan error, 1)
	go func() { startErr <- p.Start(ctx) }()
	client := &http.Client{Timeout: 5 * time.Second}
	if err := waitForProxyHealth(client, addr, startErr); err != nil {
		return err
	}

	// API route should be reachable on the main port.
	resp := doReq(t, client, http.MethodGet,
		fmt.Sprintf("http://%s/api/v1/killswitch/status", addr),
		"", map[string]string{"Authorization": "Bearer test-token-default"})
	resp.Body.Close() //nolint:errcheck,gosec // test
	// Should NOT be 404 - route is registered.
	if resp.StatusCode == http.StatusNotFound {
		t.Error("expected API route to be registered on main port when api_listen is empty")
	}
	return nil
}

// waitForProxyHealth polls /health and returns Start's error when the proxy
// exits first. A bind collision then reaches testport.WithRetry.
func waitForProxyHealth(client *http.Client, addr string, startErr <-chan error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	healthURL := fmt.Sprintf("http://%s/health", addr)
	for {
		select {
		case err := <-startErr:
			if err == nil {
				return errors.New("proxy.Start returned before /health")
			}
			return err
		default:
		}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if reqErr != nil {
			return fmt.Errorf("health request: %w", reqErr)
		}
		resp, doErr := client.Do(req)
		if doErr == nil {
			code := resp.StatusCode
			_ = resp.Body.Close()
			if code == http.StatusOK {
				return nil
			}
		}
		select {
		case err := <-startErr:
			if err == nil {
				return errors.New("proxy.Start returned before /health")
			}
			return err
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for proxy health on %s: %w", addr, ctx.Err())
		case <-ticker.C:
		}
	}
}

// TestKillSwitchHealthReportsActive verifies the /health endpoint includes
// kill_switch_active status without requiring authentication.
func TestKillSwitchHealthReportsActive(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.ApplyDefaults()

	logger, _ := audit.New("json", "stdout", "", false, false)
	defer logger.Close()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	m := metrics.New()

	ks := killswitch.New(cfg)
	p, err := New(cfg, logger, sc, m, WithKillSwitch(ks))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	// Health with kill switch inactive.
	w := httptest.NewRecorder()
	p.handleHealth(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil))
	var h1 healthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &h1); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if h1.KillSwitchActive {
		t.Error("expected kill_switch_active=false when inactive")
	}

	// A reload candidate blocks traffic before it is committed. Health has to
	// report that; the current source map still says the switch is off.
	pending := config.Defaults()
	pending.Internal = nil
	pending.KillSwitch.Enabled = true
	ks.PrepareReload(pending)
	if sources := ks.Sources(); sources["config"] {
		t.Fatal("pending kill switch must not be reported as the current config source")
	}
	w = httptest.NewRecorder()
	p.handleHealth(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil))
	var pendingHealth healthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &pendingHealth); err != nil {
		t.Fatalf("unmarshal pending health: %v", err)
	}
	if !pendingHealth.KillSwitchActive || !ks.IsActive() {
		t.Fatal("pending kill switch blocked traffic while health reported inactive")
	}
	ks.AbortReload()

	// Activate via API source.
	ks.SetAPI(true)
	w = httptest.NewRecorder()
	p.handleHealth(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil))
	var h2 healthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &h2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !h2.KillSwitchActive {
		t.Error("expected kill_switch_active=true when active")
	}
}
