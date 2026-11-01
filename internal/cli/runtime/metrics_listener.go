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

	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

// startDedicatedMetricsServer binds before returning so a configured metrics
// listener failure prevents workload launch. Empty means no network exposure.
func startDedicatedMetricsServer(ctx context.Context, listenAddr string, m *metrics.Metrics, stderr io.Writer) (func(), string, error) {
	if listenAddr == "" {
		_, _ = fmt.Fprintln(stderr, "pipelock: metrics not exposed; set metrics_listen for a dedicated listener")
		return func() {}, "", nil
	}
	if m == nil {
		return func() {}, "", fmt.Errorf("start metrics server: metrics collector is nil")
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.PrometheusHandler())
	mux.HandleFunc("/stats", m.StatsHandler())
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return func() {}, "", wrapBindError("metrics_listen", listenAddr, err)
	}
	srv := newHTTPServer(mux)
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			_, _ = fmt.Fprintf(stderr, "pipelock: metrics server stopped: %v\n", serveErr)
		}
	}()
	_, _ = fmt.Fprintf(stderr, "pipelock: metrics listening on %s\n", ln.Addr())
	stop := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}
	return stop, ln.Addr().String(), nil
}
