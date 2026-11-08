// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

type watchConnectCoverageConn struct {
	net.Conn
	input    *strings.Reader
	output   bytes.Buffer
	writeErr error
	closed   bool
}

func (c *watchConnectCoverageConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *watchConnectCoverageConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.output.Write(p)
}
func (c *watchConnectCoverageConn) Close() error                   { c.closed = true; return nil }
func (*watchConnectCoverageConn) SetDeadline(time.Time) error      { return nil }
func (*watchConnectCoverageConn) SetReadDeadline(time.Time) error  { return nil }
func (*watchConnectCoverageConn) SetWriteDeadline(time.Time) error { return nil }

type watchConnectCoverageHijacker struct {
	*httptest.ResponseRecorder
	conn  *watchConnectCoverageConn
	err   error
	calls int
}

func (w *watchConnectCoverageHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.calls++
	if w.err != nil {
		return nil, nil, w.err
	}
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestWatchConnectCoverageAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, host       string
		scanner, receipt bool
		status           int
	}{
		{name: "malformed authority", host: "invalid:port", scanner: true, status: http.StatusBadRequest},
		{name: "unavailable scanner", host: "127.0.0.1:443", status: http.StatusForbidden},
		{name: "required receipt", host: "127.0.0.1:443", scanner: true, receipt: true, status: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, p, cleanup := setupForwardProxyWithInstance(t, func(c *config.Config) { c.WatchOnly = true })
			defer cleanup()
			cfg := p.CurrentConfig().Clone()
			cfg.FlightRecorder.RequireReceipts = tc.receipt
			opts := watchHTTPOptions{Config: cfg, Proxy: p, Logger: p.logger, Metrics: p.metrics, Transport: TransportConnect}
			if tc.scanner {
				opts.Scanner = p.scannerPtr.Load()
			}
			calls := 0
			p.dialer = watchReviewDialer{call: func(context.Context) (net.Conn, error) { calls++; return nil, errors.New("unexpected dial") }}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://127.0.0.1:443", nil)
			r.Host = tc.host
			w := httptest.NewRecorder()
			p.handleWatchConnect(w, r, opts)
			if w.Code != tc.status || calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, calls, w.Body)
			}
		})
	}
}

func TestWatchConnectCoverageDeliveryFailures(t *testing.T) {
	for _, name := range []string{"no hijacker", "hijack failed", "status write failed", "SNI parse failed", "TLS required", "cache unavailable", "TLS handshake failed"} {
		t.Run(name, func(t *testing.T) {
			_, p, cleanup := setupForwardProxyWithInstance(t, func(c *config.Config) { c.WatchOnly = true; c.ForwardProxy.SNIVerification = ptrBool(false) })
			defer cleanup()
			cfg := p.CurrentConfig().Clone()
			input := "plain content that must never reach upstream"
			switch name {
			case "SNI parse failed":
				cfg.ForwardProxy.SNIVerification = ptrBool(true)
				input = "\x16"
			case "TLS required":
				cfg.ForwardProxy.SNIVerification = ptrBool(true)
				cfg.ForwardProxy.SNIRequireTLS = ptrBool(true)
			case "cache unavailable", "TLS handshake failed":
				cfg.TLSInterception.Enabled = true
				cfg.ForwardProxy.SNIRequireTLS = ptrBool(false)
			}
			if name == "TLS handshake failed" {
				cache, _, _, _, _, _ := testInterceptSetup(t)
				p.certCachePtr.Store(cache)
			}
			upstream := &watchConnectCoverageConn{input: strings.NewReader("")}
			client := &watchConnectCoverageConn{input: strings.NewReader(input)}
			calls := 0
			p.dialer = watchReviewDialer{call: func(context.Context) (net.Conn, error) { calls++; return upstream, nil }}
			recorder := httptest.NewRecorder()
			h := &watchConnectCoverageHijacker{ResponseRecorder: recorder, conn: client}
			if name == "hijack failed" {
				h.err = errors.New("hijack unavailable")
			}
			if name == "status write failed" {
				client.writeErr = io.ErrClosedPipe
			}
			var w http.ResponseWriter = h
			if name == "no hijacker" {
				w = recorder
			}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://127.0.0.1:443", nil)
			r.Host = "127.0.0.1:443"
			p.handleWatchConnect(w, r, watchHTTPOptions{Config: cfg, Scanner: p.scannerPtr.Load(), Proxy: p, Logger: p.logger, Metrics: p.metrics, Transport: TransportConnect})
			if calls != 1 || !upstream.closed || upstream.output.Len() != 0 {
				t.Fatalf("upstream calls=%d closed=%v bytes=%q", calls, upstream.closed, upstream.output.String())
			}
			if name == "no hijacker" {
				if recorder.Code != http.StatusInternalServerError {
					t.Fatalf("status=%d", recorder.Code)
				}
				return
			}
			if h.calls != 1 {
				t.Fatalf("hijacks=%d", h.calls)
			}
			if name == "hijack failed" {
				if client.output.Len() != 0 {
					t.Fatal("wrote success after failed hijack")
				}
				return
			}
			if !client.closed {
				t.Fatal("failed tunnel left client open")
			}
			if name == "status write failed" {
				if client.output.Len() != 0 {
					t.Fatal("wrote after client failure")
				}
				return
			}
			if !strings.HasPrefix(client.output.String(), "HTTP/1.1 200 Connection Established\r\n\r\n") {
				t.Fatalf("handshake=%q", client.output.String())
			}
		})
	}
}

func TestWatchAdmissionLiveFloors(t *testing.T) {
	for _, transport := range []string{TransportConnect, TransportForward, TransportFetch} {
		for _, floor := range []string{"kill switch", "inbound verifier"} {
			t.Run(transport+"/"+floor, func(t *testing.T) {
				_, p, cleanup := setupForwardProxyWithInstance(t, func(c *config.Config) { c.WatchOnly = true })
				defer cleanup()
				cfg := p.CurrentConfig().Clone()
				cfg.MediationEnvelope.VerifyInbound.Enabled = floor == "inbound verifier"
				ks := killswitch.New(cfg)
				ks.SetAPI(floor == "kill switch")
				want := http.StatusForbidden
				if floor == "kill switch" {
					want = http.StatusServiceUnavailable
				}
				calls := 0
				p.dialer = watchReviewDialer{call: func(context.Context) (net.Conn, error) { calls++; return nil, errors.New("unexpected dial") }}
				rt := roundTripperFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected request") })
				p.client.Transport = rt
				opts := watchHTTPOptions{Config: cfg, Scanner: p.scannerPtr.Load(), Proxy: p, KillSwitch: ks, Logger: p.logger, Metrics: p.metrics, Transport: transport, Upstream: rt}
				w := httptest.NewRecorder()
				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/data", nil)
				switch transport {
				case TransportConnect:
					r.Method = http.MethodConnect
					r.Host = "127.0.0.1:443"
					p.handleWatchConnect(w, r, opts)
				case TransportFetch:
					r = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.example/fetch?url=http://api.vendor.example/data", nil)
					p.handleWatchFetch(w, r, opts)
				default:
					serveWatchHTTP(w, r, opts)
				}
				if calls != 0 || w.Code != want || w.Body.Len() == 0 {
					t.Fatalf("floor escaped: calls=%d status=%d body=%s", calls, w.Code, w.Body)
				}
			})
		}
	}
}
