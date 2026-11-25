// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func newContainmentMetricsTestServer(t *testing.T, metricsListen, webhookURL string) (*Server, *syncBuffer) {
	s, output := newContainmentMetricsTestServerWithFetch(t, metricsListen, webhookURL, "")
	t.Cleanup(s.cleanup)
	return s, output
}

func newContainmentMetricsTestServerWithFetch(t *testing.T, metricsListen, webhookURL, fetchListen string) (*Server, *syncBuffer) {
	t.Helper()
	lines := []string{
		"mode: balanced",
		"metrics_listen: " + fmt.Sprintf("%q", metricsListen),
	}
	if webhookURL != "" {
		lines = append(lines,
			"emit:",
			"  webhook:",
			"    url: "+fmt.Sprintf("%q", webhookURL),
			"    min_severity: warn",
			"    timeout_seconds: 1",
			"    queue_size: 16",
		)
	}
	buf := &syncBuffer{}
	s, err := NewServer(ServerOpts{
		ConfigFile:                        writeServerTestConfig(t, strings.Join(lines, "\n")+"\n"),
		Listen:                            fetchListen,
		ListenChanged:                     fetchListen != "",
		Stdout:                            buf,
		Stderr:                            buf,
		allowEphemeralListenersForTesting: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s, buf
}

// startContainmentMetricsTestServer joins Start before earlier test cleanups
// restore the environment or remove its config. Start owns server resource cleanup.
func startContainmentMetricsTestServer(t *testing.T, s *Server) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	returned := make(chan struct{})
	t.Cleanup(func() {
		// Cancel the parent too: Shutdown is a no-op if Start hasn't run yet.
		cancel()
		select {
		case <-returned:
		case <-time.After(testwait.Deadline(10 * time.Second)):
			t.Error("contained proxy Start did not return before cleanup")
		}
	})
	go func() {
		defer close(returned)
		done <- s.Start(ctx)
	}()
	return done
}

func TestServer_ContainmentMetricsCleanupWaitsForStart(t *testing.T) {
	for _, waitForStartup := range []bool{false, true} {
		t.Run(fmt.Sprintf("wait_for_startup_%t", waitForStartup), func(t *testing.T) {
			t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
			// Nothing dials the fetch listener, so Start picks the port.
			s, _ := newContainmentMetricsTestServerWithFetch(t, "", "", serverTestEphemeralListen)
			var done <-chan error
			// Registered first, this must run after the cancel-and-join cleanup.
			t.Cleanup(func() {
				select {
				case err := <-done:
					t.Logf("goroutine result: %v", err)
				default:
					t.Error("test cleanup ran before Start returned")
				}
			})
			done = startContainmentMetricsTestServer(t, s)
			if waitForStartup {
				select {
				case <-s.startupNotified():
				case err := <-done:
					t.Fatalf("Start returned before startup: %v", err)
				case <-time.After(testwait.Deadline(3 * time.Second)):
					t.Fatal("timed out waiting for contained proxy startup")
				}
			}
			// Return without Shutdown, as an assertion failure would.
		})
	}
}

// containmentProxyReady waits for s to bind its listeners before polling the
// proxy health URL, and returns Start's error when the server exits first.
// Waiting on startupNotified prevents a port thief already serving /health from
// masking Start's EADDRINUSE inside testport.WithRetry.
func containmentProxyReady(s *Server, client *http.Client, addr string, done <-chan error, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(timeout))
	defer cancel()
	select {
	case <-s.startupNotified():
	case err := <-done:
		return fmt.Errorf("Start returned before serving the proxy: %w", err)
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for contained proxy on %s: %w", addr, ctx.Err())
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	healthURL := "http://" + addr + "/health"
	for {
		select {
		case err := <-done:
			return fmt.Errorf("Start returned before serving the proxy: %w", err)
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
		case err := <-done:
			return fmt.Errorf("Start returned before serving the proxy: %w", err)
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for contained proxy on %s: %w", addr, ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestServer_StartContainmentUnsafeMetricsSkipsBlockedListener(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	metricsBlocker, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = metricsBlocker.Close() }()
	metricsPort := metricsBlocker.Addr().(*net.TCPAddr).Port
	metricsListen := net.JoinHostPort("0.0.0.0", strconv.Itoa(metricsPort))
	testport.WithRetry(t, 1, func(addrs []string) error {
		fetchListen := addrs[0]
		s, _ := newContainmentMetricsTestServerWithFetch(t, metricsListen, "", fetchListen)

		done := startContainmentMetricsTestServer(t, s)

		client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 200 * time.Millisecond}
		t.Cleanup(client.CloseIdleConnections)
		if err := containmentProxyReady(s, client, fetchListen, done, 2*time.Second); err != nil {
			return err
		}

		client.CloseIdleConnections()
		if err := s.Shutdown(context.Background()); err != nil {
			return fmt.Errorf("Shutdown: %w", err)
		}
		select {
		case startErr := <-done:
			if startErr != nil {
				return fmt.Errorf("Start: %w", startErr)
			}
		case <-time.After(testwait.Deadline(6 * time.Second)):
			return fmt.Errorf("timed out waiting for contained proxy shutdown")
		}
		return nil
	})
}

func TestNewServer_ContainmentUnsafeMetricsDisablesListenerAndReportsCritical(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	webhookURL, events := newServerTestWebhook(t)
	s, stderr := newContainmentMetricsTestServer(t, "0.0.0.0:19091", webhookURL)

	if !s.containmentManaged {
		t.Fatal("managed containment environment was not recognized")
	}
	if !s.metricsDisabled {
		t.Fatal("unsafe containment metrics listener remained enabled")
	}
	if got := s.proxy.CurrentConfig().MetricsListen; got == "" {
		t.Fatal("unsafe metrics listener was cleared, which would expose metrics on the proxy port")
	}
	if !stderr.contains("CRITICAL: containment managed config drift") {
		t.Fatalf("critical containment drift was not reported:\n%s", stderr.String())
	}

	deadline := time.NewTimer(testwait.Deadline(3 * time.Second))
	defer deadline.Stop()
	for {
		select {
		case event := <-events:
			if event.Type != containmentMetricsDriftEvent {
				continue
			}
			if event.Severity != "critical" {
				t.Fatalf("event severity = %q, want critical", event.Severity)
			}
			if event.Fields["outcome"] != "metrics_disabled" {
				t.Fatalf("event outcome = %v, want metrics_disabled", event.Fields["outcome"])
			}
			return
		case <-deadline.C:
			t.Fatal("timed out waiting for critical containment metrics drift event")
		}
	}
}

func TestNewServer_ContainmentLoopbackMetricsRemainEnabled(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	s, stderr := newContainmentMetricsTestServer(t, "127.0.0.1:19091", "")

	if !s.containmentManaged {
		t.Fatal("managed containment environment was not recognized")
	}
	if s.metricsDisabled {
		t.Fatal("compliant loopback metrics listener was disabled")
	}
	if stderr.contains("containment managed config drift") {
		t.Fatalf("compliant loopback metrics listener reported drift:\n%s", stderr.String())
	}
}

func TestServer_ReloadContainmentUnsafeMetricsRejectsAndReportsCritical(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	s, stderr := newContainmentMetricsTestServer(t, "127.0.0.1:19091", "")
	oldCfg := s.proxy.CurrentConfig()
	newCfg := oldCfg.Clone()
	newCfg.MetricsListen = "0.0.0.0:19092"

	if err := s.Reload(newCfg); err == nil {
		t.Fatal("Reload accepted an unsafe containment metrics listener")
	}
	if got := s.proxy.CurrentConfig().MetricsListen; got != oldCfg.MetricsListen {
		t.Fatalf("live metrics listener = %q, want preserved %q", got, oldCfg.MetricsListen)
	}
	if !stderr.contains("CRITICAL: containment managed config drift") {
		t.Fatalf("unsafe reload did not report critical containment drift:\n%s", stderr.String())
	}
}
