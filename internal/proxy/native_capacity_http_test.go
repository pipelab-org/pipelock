// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type cutoffFlushWriter struct {
	http.ResponseWriter
	flushing chan struct{}
	expired  chan struct{}
	once     sync.Once
}

func (w *cutoffFlushWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *cutoffFlushWriter) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		w.once.Do(func() { close(w.expired) })
	}
	return nil
}

func (w *cutoffFlushWriter) FlushError() error {
	close(w.flushing)
	<-w.expired
	return context.DeadlineExceeded
}

func TestNativeCapacityBoundsBestEffortFetchFinalFlush(t *testing.T) {
	p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4, func(cfg *config.Config) {
		cfg.FlightRecorder.RequireReceipts = false
	})
	p.shutdownGrace = 50 * time.Millisecond
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.WriteString(w, "fixture fetch response"); err != nil {
			t.Error(err)
		}
	}))
	defer upstream.Close()
	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	w := &cutoffFlushWriter{ResponseWriter: httptest.NewRecorder(), flushing: make(chan struct{}), expired: make(chan struct{})}
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(2*time.Second))
	defer cancel()
	t.Cleanup(func() { w.once.Do(func() { close(w.expired) }) })
	target := "http://api.vendor.example:" + port + "/"
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/fetch?url="+url.QueryEscape(target), nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.handleFetch(w, req)
	}()
	select {
	case <-w.flushing:
	case <-done:
		t.Fatal("handler returned before the capacity-bounded final flush")
	case <-ctx.Done():
		t.Fatal("fetch did not reach final flush")
	}
	if _, err := e.ReserveNativeRecords(2 * nativeRequestRecords); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("stop = %v, want %v", err, ael.ErrCapacity)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("final fetch flush outlived capacity grace")
	}
	verifyNativeCapacityClose(t, e, dir)
}

func TestNativeCapacityRecordsBestEffortDownloadCutoff(t *testing.T) {
	const host = "api.vendor.example"
	for _, transport := range []string{TransportForward, "intercept"} {
		t.Run(transport, func(t *testing.T) {
			p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4, func(cfg *config.Config) {
				cfg.FlightRecorder.RequireReceipts = false
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.ExemptDomains = []string{host}
			})
			p.shutdownGrace = 50 * time.Millisecond
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(3*time.Second))
			defer cancel()
			const firstSize = 8192
			first := strings.Repeat("d", firstSize)
			canceled := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Length", "16384")
				if _, err := io.WriteString(w, first); err != nil {
					t.Error(err)
					return
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Error(err)
					return
				}
				select {
				case <-r.Context().Done():
					close(canceled)
				case <-ctx.Done():
				}
			}))
			defer upstream.Close()
			dst, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := *dst
			dst.Host = host + ":" + dst.Port()
			handler := p.Handler()
			if transport == "intercept" {
				ic := &InterceptContext{
					TargetHost: dst.Hostname(), TargetPort: dst.Port(), Config: p.CurrentConfig(),
					Scanner: p.ScannerPtr().Load(), Logger: p.logger, Metrics: p.metrics, Proxy: p,
				}
				handler = newInterceptHandler(ic, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					out := req.Clone(req.Context())
					out.URL.Scheme, out.URL.Host = endpoint.Scheme, endpoint.Host
					return upstream.Client().Transport.RoundTrip(out)
				}))
			}
			proxyServer := httptest.NewServer(handler)
			defer proxyServer.Close()
			client := proxyServer.Client()
			target := proxyServer.URL + "/"
			if transport == TransportForward {
				proxyURL, err := url.Parse(proxyServer.URL)
				if err != nil {
					t.Fatal(err)
				}
				rt := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
				defer rt.CloseIdleConnections()
				client = &http.Client{Transport: rt}
				target = dst.String()
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if transport == "intercept" {
				request.Host = dst.Host
			}
			resp, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Error(err)
				}
			}()
			const prefixSize = 1024
			got := make([]byte, prefixSize)
			if _, err := io.ReadFull(resp.Body, got); err != nil || string(got) != first[:prefixSize] || resp.StatusCode != http.StatusOK {
				t.Fatalf("initial download: status=%d bytes=%d error=%v", resp.StatusCode, len(got), err)
			}
			if _, err := e.ReserveNativeRecords(2 * nativeRequestRecords); !errors.Is(err, ael.ErrCapacity) {
				t.Fatalf("stop = %v, want %v", err, ael.ErrCapacity)
			}
			select {
			case <-canceled:
			case <-ctx.Done():
				t.Fatal("download cutoff did not cancel upstream")
			}
			if n, err := io.Copy(io.Discard, resp.Body); n > firstSize-prefixSize || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("download after cutoff: bytes=%d error=%v", n, err)
			}
			waitCapacityDrain(t, ctx, e)
			verifyNativeCapacityClose(t, e, dir)
			verifyNativeStreamOutcome(t, e, dir, transport, false)
		})
	}
}

type sseCutoffReader struct {
	cancel context.CancelCauseFunc
	err    error
}

func (r sseCutoffReader) Read([]byte) (int, error) {
	r.cancel(ael.ErrCapacity)
	return 0, r.err
}

func TestDispatchSSEScanDistinguishesCapacityFromScanFailure(t *testing.T) {
	p, _, _ := newNativeCapacityProxy(t, nativeRequestRecords+4)
	for _, tc := range []struct {
		name  string
		cause error
		want  error
	}{
		{"interrupted scan", fmt.Errorf("%w: %w", mcp.ErrSSEStreamScanError, context.Canceled), ael.ErrCapacity},
		{"independent scan failure", fmt.Errorf("%w: inspection incomplete", mcp.ErrSSEStreamScanError), mcp.ErrSSEStreamScanError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			err := DispatchSSEScan(ctx, sseCutoffReader{cancel: cancel, err: tc.cause}, io.Discard, nil,
				p.ScannerPtr().Load(), SSEDispatchOptions{GenericSSE: &config.GenericSSEScanning{Enabled: true}})
			if !errors.Is(err, tc.want) {
				t.Fatalf("dispatch error=%v, want %v", err, tc.want)
			}
		})
	}
}
