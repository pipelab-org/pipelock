// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"io"
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
			body := "mode: balanced\n"
			metricsAddr := ""
			switch value {
			case "null":
				body += "metrics_listen: null\n"
			case "blank":
				body += "metrics_listen: ''\n"
			case "configured":
				metricsAddr = testport.ListenAddrs(t, 1)[0]
				body += fmt.Sprintf("metrics_listen: %q\n", metricsAddr)
			}
			path := writeServerTestConfig(t, body)
			s, output := newTestServer(t, func(o *ServerOpts) {
				o.ConfigFile = path
				o.Listen = serverTestEphemeralListen
				o.ListenChanged = true
			})
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- s.Start(ctx) }()
			defer func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("Start: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Error("server shutdown exceeded deadline")
				}
			}()
			waitForServerOutput(t, output, "  Health: http://")
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
			candidate.MetricsListen = testport.ListenAddrs(t, 1)[0]
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
		})
	}
}

func TestDedicatedMetricsListenerStatsAndCleanup(t *testing.T) {
	var output strings.Builder
	stop, err := startDedicatedMetricsServer(t.Context(), "127.0.0.1:0", metrics.New(), &output)
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
