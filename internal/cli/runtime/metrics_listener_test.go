// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestServerMetricsRequireDedicatedListener(t *testing.T) {
	for _, value := range []string{"omitted", "null", "blank", "configured"} {
		t.Run(value, func(t *testing.T) {
			if value == "configured" {
				testport.WithRetry(t, 1, func(addrs []string) error {
					return exerciseServerMetricsDedicatedListener(t, value, addrs[0])
				})
				return
			}
			if err := exerciseServerMetricsDedicatedListener(t, value, ""); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestServerMetricsDedicatedListenerReturnsBindCollisionForRetry(t *testing.T) {
	blocker, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Close() }()

	gotErr := exerciseServerMetricsDedicatedListener(t, "configured", blocker.Addr().String())
	if !testport.IsBindCollision(gotErr) {
		t.Fatalf("occupied metrics_listen error = %v, want bind collision so testport.WithRetry retries", gotErr)
	}
}

func exerciseServerMetricsDedicatedListener(t *testing.T, value, metricsAddr string) (retErr error) {
	t.Helper()
	body := "mode: balanced\n"
	switch value {
	case "null":
		body += "metrics_listen: null\n"
	case "blank":
		body += "metrics_listen: ''\n"
	case "configured":
		body += fmt.Sprintf("metrics_listen: %q\n", metricsAddr)
	}
	path := writeServerTestConfig(t, body)
	s, output := newTestServerForStart(t, func(o *ServerOpts) {
		o.ConfigFile = path
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := runJoined(t, ctx, s.Start, nil)
	var consumedStart bool
	defer func() {
		cancel()
		if consumedStart {
			return
		}
		select {
		case err := <-done:
			if err != nil && retErr == nil {
				retErr = fmt.Errorf("Start: %w", err)
			}
		case <-time.After(testwait.Deadline(10 * time.Second)):
			if retErr == nil {
				retErr = errors.New("server shutdown exceeded deadline")
			}
		}
	}()
	// Wait for startupNotified rather than the Health banner: Start prints
	// Health after binding the ephemeral fetch listener and before binding
	// metrics_listen, so polling the banner races a metrics_listen bind
	// collision and turns it into a health-poll timeout instead of a retry.
	select {
	case <-s.startupNotified():
	case startErr := <-done:
		consumedStart = true
		return fmt.Errorf("Start exited before startup: %w\n%s", startErr, output.String())
	case <-time.After(testwait.Deadline(5 * time.Second)):
		return fmt.Errorf("timed out waiting for server startup:\n%s", output.String())
	}
	agentURL := ""
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "  Health: ") {
			agentURL = strings.TrimSuffix(strings.TrimPrefix(line, "  Health: "), "/health")
		}
	}
	if agentURL == "" {
		t.Fatal("missing bound health URL")
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	status := func(url string) int {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	testwait.For(t, 5*time.Second, func() bool { return status(agentURL+"/health") == http.StatusOK }, "run listener health")
	assertRoutes := func() {
		t.Helper()
		for _, route := range []string{"/metrics", "/stats"} {
			if got := status(agentURL + route); got != http.StatusNotFound {
				t.Fatalf("agent %s = %d", route, got)
			}
			if metricsAddr != "" && status("http://"+metricsAddr+route) != http.StatusOK {
				t.Fatalf("dedicated %s unavailable", route)
			}
		}
	}
	assertRoutes()
	candidate := s.cfg.Clone()
	explain := true
	candidate.ExplainBlocks = &explain
	if err := s.Reload(candidate); err != nil {
		t.Fatal(err)
	}
	assertRoutes()
	candidate = candidate.Clone()
	// Nothing dials this address. Reload reports the change and
	// keeps the listener that already bound.
	candidate.MetricsListen = "127.0.0.1:0"
	if err := s.Reload(candidate); err != nil {
		t.Fatal(err)
	}
	if s.proxy.CurrentConfig().MetricsListen != metricsAddr || !output.contains("metrics_listen changed") {
		t.Fatal("metrics address changed without restart")
	}
	assertRoutes()
	if metricsAddr == "" {
		if output.contains("metrics listening on") || !output.contains("not exposed; set metrics_listen") {
			t.Fatal("unexpected metrics exposure notice: " + output.String())
		}
	}
	return nil
}

func TestDedicatedMetricsListenerStatsAndCleanup(t *testing.T) {
	var output strings.Builder
	stop, _, err := startDedicatedMetricsServer(t.Context(), "127.0.0.1:0", metrics.New(), &output)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	addr := strings.TrimSpace(strings.TrimPrefix(output.String(), "pipelock: metrics listening on "))
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for _, route := range []string{"/metrics", "/stats"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+route, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK || len(body) == 0 {
			t.Fatalf("%s = %d, %v", route, resp.StatusCode, readErr)
		}
	}
	stop()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/stats", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("listener survived cleanup")
	}
}
