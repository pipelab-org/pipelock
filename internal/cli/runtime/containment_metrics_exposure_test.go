// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// TestServer_ContainmentDeletedMetricsKeyDoesNotExposeMetricsOnTheProxyPort
// covers the state an operator actually reaches by following the remediation
// message: they delete metrics_listen instead of setting it.
//
// Deleting the key is not the same as setting an unsafe address. An unsafe
// address leaves the value non-empty, and the proxy only publishes /metrics and
// /stats on its own listener when the value is EMPTY. So the deleted-key case
// is the one where disabling the dedicated listener silently hands the endpoints
// to the agent-reachable proxy port, while startup still reports metrics
// disabled. That combination is worse than an unguarded host, because the
// operator has been told they are covered.
func TestServer_ContainmentDeletedMetricsKeyDoesNotExposeMetricsOnTheProxyPort(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	testport.WithRetry(t, 1, func(addrs []string) error {
		fetchListen := addrs[0]
		// The empty address is the deleted key: config.Load leaves it "".
		// Start owns resource cleanup; the test cleanup cancels and joins Start.
		output := &syncBuffer{}
		s, err := NewServer(ServerOpts{
			ConfigFile:                        writeServerTestConfig(t, "mode: balanced\nmetrics_listen: ''\n"),
			Listen:                            fetchListen,
			ListenChanged:                     true,
			Stdout:                            output,
			Stderr:                            output,
			allowEphemeralListenersForTesting: true,
		})
		if err != nil {
			return fmt.Errorf("NewServer: %w", err)
		}

		done := startContainmentMetricsTestServer(t, s)

		client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 500 * time.Millisecond}
		t.Cleanup(client.CloseIdleConnections)
		get := func(path string) (int, bool) {
			request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+fetchListen+path, nil)
			if err != nil {
				return 0, false
			}
			resp, requestErr := client.Do(request)
			if requestErr != nil {
				return 0, false
			}
			defer func() { _ = resp.Body.Close() }()
			return resp.StatusCode, true
		}

		if err := containmentProxyReady(s, client, fetchListen, done, 3*time.Second); err != nil {
			return err
		}

		for _, path := range []string{"/metrics", "/stats"} {
			code, ok := get(path)
			if !ok {
				return fmt.Errorf("%s: request failed against a proxy that is serving /health", path)
			}
			if code != http.StatusNotFound {
				return fmt.Errorf("%s on the agent-reachable proxy port returned %d, want 404: containment reported metrics disabled, "+
					"so the contained agent must not be able to read them here", path, code)
			}
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
		// Match the containment metrics policy test: a new HTTP connection can
		// consume the proxy's five-second graceful shutdown window before returning.
		case <-time.After(testwait.Deadline(6 * time.Second)):
			return fmt.Errorf("timed out waiting for contained proxy shutdown")
		}
		return nil
	})
}
