// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestConnectDefersOnlyInterceptedDial(t *testing.T) {
	// A refused outbound dial must not prevent a locally terminated browser
	// preconnect. Raw tunnels still require the upstream connection first.
	target, _ := dialFallbackListener(t)
	numericAuthority := net.JoinHostPort("127.0.0.1", target)
	for _, tc := range []struct {
		name              string
		host              string
		intercept, pass   bool
		metrics           bool
		wantStatus, dials int
	}{
		{name: "intercept", intercept: true, wantStatus: http.StatusOK},
		{name: "raw", wantStatus: http.StatusBadGateway, dials: 1},
		{name: "passthrough", intercept: true, pass: true, wantStatus: http.StatusBadGateway, dials: 1},
		{name: "intercept metrics floor", intercept: true, metrics: true, wantStatus: http.StatusForbidden},
		{name: "intercept DNS metrics floor", host: "metrics.vendor.example", intercept: true, metrics: true, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authority := numericAuthority
			if tc.host != "" {
				authority = net.JoinHostPort(tc.host, target)
			}
			addr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				cfg.TLSInterception.Enabled = tc.intercept
				if tc.pass {
					cfg.TLSInterception.PassthroughDomains = []string{"127.0.0.1"}
				}
				if tc.metrics {
					cfg.MetricsListen = numericAuthority
				}
				if tc.host != "" {
					cfg.DNS.HostOverrides = map[string][]string{tc.host: {"127.0.0.1"}}
				}
			})
			defer cleanup()
			var attempts atomic.Int32
			p.dialer = &net.Dialer{Control: func(string, string, syscall.RawConn) error {
				attempts.Add(1)
				return net.ErrClosed
			}}
			conn := dialProxy(t, addr)
			defer func() { _ = conn.Close() }()
			if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.wantStatus || int(attempts.Load()) != tc.dials {
				t.Fatalf("status=%d dials=%d, want status=%d dials=%d", resp.StatusCode, attempts.Load(), tc.wantStatus, tc.dials)
			}
			if tc.metrics && resp.Header.Get(blockreason.HeaderReason) != string(blockreason.SSRFPrivateIP) {
				t.Fatalf("metrics refusal lost SSRF reason: %v", resp.Header)
			}
		})
	}
}

type dialTargetTestResolver func(context.Context, string) ([]string, error)

func (f dialTargetTestResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return f(ctx, host)
}

func TestResolveAndValidateDialTargetResolverFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ips    []string
		err    error
		cancel bool
	}{
		{name: "resolver error", err: errors.New("resolver failure")},
		{name: "empty answer"},
		{name: "malformed answer", ips: []string{"not-an-address"}},
		{name: "cancelled answer", ips: []string{"203.0.113.10"}, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			sc, err := scanner.NewWithOptions(config.Defaults(), scanner.Options{UpstreamResolver: dialTargetTestResolver(func(context.Context, string) ([]string, error) {
				if tc.cancel {
					cancel()
				}
				return tc.ips, tc.err
			})})
			if err != nil {
				t.Fatal(err)
			}
			defer sc.Close()
			p := dialFallbackProxy(t, "127.0.0.1")
			ctx = context.WithValue(ctx, ctxKeyAgentScanner, sc)
			target, err := p.resolveAndValidateDialTarget(ctx, dialFallbackHost+":443")
			if err == nil || len(target.addrs) != 0 {
				t.Fatalf("target=%+v error=%v, want no resolved authority", target, err)
			}
			if tc.cancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled resolver returned %v", err)
			}
		})
	}
}

func TestDeferredDialRevalidatesDestination(t *testing.T) {
	var lookups atomic.Int32
	sc, err := scanner.NewWithOptions(config.Defaults(), scanner.Options{UpstreamResolver: dialTargetTestResolver(func(context.Context, string) ([]string, error) {
		if lookups.Add(1) == 1 {
			return []string{"203.0.113.10"}, nil
		}
		return []string{"169.254.169.254"}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	p := dialFallbackProxy(t, "127.0.0.1")
	var attempts atomic.Int32
	p.dialer = &net.Dialer{Control: func(string, string, syscall.RawConn) error {
		attempts.Add(1)
		return net.ErrClosed
	}}
	ctx := context.WithValue(t.Context(), ctxKeyAgentScanner, sc)
	if _, err := p.resolveAndValidateDialTarget(ctx, dialFallbackHost+":443"); err != nil {
		t.Fatalf("initial destination validation: %v", err)
	}
	conn, err := p.ssrfSafeDialContext(ctx, "tcp", dialFallbackHost+":443")
	if conn != nil {
		_ = conn.Close()
	}
	var blocked *ssrfDialBlockError
	if !errors.As(err, &blocked) || lookups.Load() != 2 || attempts.Load() != 0 {
		t.Fatalf("changed destination: error=%v lookups=%d socket attempts=%d", err, lookups.Load(), attempts.Load())
	}
}

func TestResolveAndValidateDialTarget(t *testing.T) {
	for _, tc := range []struct {
		name, authority string
		ips             []string
		wantBlock       bool
	}{
		{"literal", "127.0.0.1:443", []string{"127.0.0.1"}, false},
		{"DNS", dialFallbackHost + ":443", []string{"127.0.0.1", "127.0.0.2"}, false},
		{"metadata literal", "169.254.169.254:443", []string{"127.0.0.1"}, true},
		{"mapped metadata", "[::ffff:169.254.169.254]:443", []string{"127.0.0.1"}, true},
		{"last DNS address blocked", dialFallbackHost + ":443", []string{"127.0.0.1", "169.254.169.254"}, true},
		{"first DNS address blocked", dialFallbackHost + ":443", []string{"169.254.169.254", "127.0.0.1"}, true},
		{"internal DNS address", dialFallbackHost + ":443", []string{"10.0.0.1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := dialFallbackProxy(t, tc.ips...)
			var attempts atomic.Int32
			p.dialer = &net.Dialer{Control: func(string, string, syscall.RawConn) error {
				attempts.Add(1)
				return net.ErrClosed
			}}
			t.Cleanup(func() {
				if attempts.Load() != 0 {
					t.Errorf("validation opened %d sockets", attempts.Load())
				}
			})
			target, err := p.resolveAndValidateDialTarget(t.Context(), tc.authority)
			if tc.wantBlock {
				var blocked *ssrfDialBlockError
				if !errors.As(err, &blocked) || len(target.addrs) != 0 {
					t.Fatalf("target=%+v error=%v, want no addresses and SSRF refusal", target, err)
				}
				return
			}
			if err != nil || len(target.addrs) != len(tc.ips) {
				t.Fatalf("target=%+v error=%v", target, err)
			}
		})
	}
	t.Run("cancelled literal", func(t *testing.T) {
		p := dialFallbackProxy(t, "127.0.0.1")
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := p.resolveAndValidateDialTarget(ctx, "127.0.0.1:443"); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled validation returned %v", err)
		}
	})
}

func TestConnectInterceptSingleUpstreamConnection(t *testing.T) {
	var upstreamConnections atomic.Int32
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ordinary response")
	}))
	backend.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			upstreamConnections.Add(1)
		}
	}
	backend.StartTLS()
	defer backend.Close()
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(backend.Certificate())
	addr, clientPool, cleanup := setupForwardProxyWithTLS(t, nil, upstreamPool)
	defer cleanup()
	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientPool}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, backend.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "ordinary response") {
		t.Fatalf("status=%d body=%q error=%v", resp.StatusCode, body, err)
	}
	if got := upstreamConnections.Load(); got != 1 {
		t.Fatalf("one intercepted request opened %d upstream connections, want 1", got)
	}
}
