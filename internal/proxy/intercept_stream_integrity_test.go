// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Record upstream bytes without changing HTTP/2 framing or handling.
type interceptFrameConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *interceptFrameConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	_, _ = c.buf.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

// interceptFrameListener records the one accepted connection. Go 1.26 attaches
// TLS HTTP/2 only to a concrete *tls.Conn, so a wrapper cannot record decrypted
// bytes and stay on that path. Prior-knowledge HTTP/2 serves any net.Conn on
// both supported Go versions.
type interceptFrameListener struct {
	net.Listener
	conn *interceptFrameConn
}

func (l *interceptFrameListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.conn.Conn != nil {
		_ = c.Close()
		return nil, fmt.Errorf("upstream accepted a second connection")
	}
	l.conn.Conn = c
	return l.conn, nil
}

func startObservedHTTP2Upstream(t *testing.T, handler http.Handler) (*http.Transport, *interceptFrameConn) {
	t.Helper()
	raw, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	observed := &interceptFrameConn{}
	serverProtocols := new(http.Protocols)
	serverProtocols.SetHTTP1(true)
	serverProtocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Handler:           handler,
		Protocols:         serverProtocols,
		ReadHeaderTimeout: 5 * time.Second,
	}
	serveDone := make(chan struct{})
	go func() {
		_ = srv.Serve(&interceptFrameListener{Listener: raw, conn: observed})
		close(serveDone)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-serveDone
	})
	clientProtocols := new(http.Protocols)
	clientProtocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{
		Protocols: clientProtocols,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, raw.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return transport, observed
}

func (c *interceptFrameConn) requestFrames() (bool, int, error) {
	c.mu.Lock()
	data := bytes.Clone(c.buf.Bytes())
	c.mu.Unlock()
	if !bytes.HasPrefix(data, []byte(http2.ClientPreface)) {
		return false, 0, fmt.Errorf("missing HTTP/2 client preface")
	}
	f := http2.NewFramer(nil, bytes.NewReader(data[len(http2.ClientPreface):]))
	var endStream bool
	var dataFrames int
	for {
		frame, err := f.ReadFrame()
		if err != nil {
			return endStream, dataFrames, err
		}
		if frame.Header().StreamID != 1 {
			continue
		}
		switch frame := frame.(type) {
		case *http2.HeadersFrame:
			endStream = frame.StreamEnded()
			if endStream {
				return true, dataFrames, nil
			}
		case *http2.DataFrame:
			dataFrames++
			if frame.StreamEnded() {
				return endStream, dataFrames, nil
			}
		}
	}
}

func TestInterceptTunnelRequestBodyFraming(t *testing.T) {
	for _, tc := range []struct {
		name          string
		proto         int
		method        string
		body          string
		unknownLength bool
		scan          bool
		bodyHeader    bool
	}{
		{name: "h2_empty_get", proto: 2, method: http.MethodGet},
		{name: "h1_empty_get", proto: 1, method: http.MethodGet},
		{name: "h2_empty_get_scanned", proto: 2, method: http.MethodGet, scan: true},
		{name: "h2_get_body_header", proto: 2, method: http.MethodGet, bodyHeader: true},
		{name: "h2_post", proto: 2, method: http.MethodPost, body: "ordinary request bytes"},
		{name: "h2_post_scanned", proto: 2, method: http.MethodPost, body: "ordinary request bytes", scan: true},
		{name: "h2_post_unknown_length", proto: 2, method: http.MethodPost, body: "ordinary request bytes", unknownLength: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type observation struct {
				body         string
				lengthHeader string
				endStream    bool
				dataFrames   int
				err          error
			}
			seen := make(chan observation, 1)
			var recorded *interceptFrameConn
			upstreamTransport, recorded := startObservedHTTP2Upstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				endStream, frames, frameErr := recorded.requestFrames()
				if err == nil {
					err = frameErr
				}
				seen <- observation{body: string(body), lengthHeader: r.Header.Get("Content-Length"), endStream: endStream, dataFrames: frames, err: err}
				if r.ProtoMajor != 2 || (r.Method == http.MethodGet && (!endStream || frames != 0 || r.Header.Get("Content-Length") != "")) {
					http.Error(w, "unexpected request body framing", http.StatusBadRequest)
					return
				}
				_, _ = io.WriteString(w, "accepted")
			}))

			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			cfg.RequestBodyScanning.Enabled = tc.scan
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			clientConn, proxyConn := net.Pipe()
			t.Cleanup(func() { _ = clientConn.Close(); _ = proxyConn.Close() })
			tunnelDone := make(chan error, 1)
			go func() {
				tunnelDone <- interceptTunnel(t.Context(), proxyConn, &InterceptContext{
					TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc,
					CertCache: cache, Logger: logger, Metrics: m,
					UpstreamRT: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
						if tc.method == http.MethodGet && (r.Body != nil || r.GetBody != nil) {
							t.Error("zero-length GET must have no Body or GetBody at round trip")
						}
						if tc.unknownLength && r.ContentLength != -1 {
							t.Errorf("unknown body length=%d, want -1", r.ContentLength)
						}
						// Prior-knowledge HTTP/2 is selected for http URLs. Leave the body alone.
						r.URL.Scheme = "http"
						return upstreamTransport.RoundTrip(r)
					}), RequestID: "request-body-framing",
				})
			}()
			tr := &http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2: tc.proto == 2,
				DialContext:       func(context.Context, string, string) (net.Conn, error) { return clientConn, nil },
			}
			t.Cleanup(tr.CloseIdleConnections)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
				if tc.unknownLength {
					body = struct{ io.Reader }{body}
				}
			}
			req, err := http.NewRequestWithContext(ctx, tc.method, "https://api.vendor.example/payload", body)
			if err != nil {
				t.Fatal(err)
			}
			if tc.bodyHeader {
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Content-Length", "0")
			}
			resp, err := (&http.Client{Transport: tr}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			responseBody, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-seen:
				t.Logf("upstream h2: HEADERS END_STREAM=%t DATA frames=%d content-length=%q body=%q", got.endStream, got.dataFrames, got.lengthHeader, got.body)
				if got.err != nil {
					t.Fatal(got.err)
				}
				if got.body != tc.body {
					t.Errorf("upstream body=%q, want %q", got.body, tc.body)
				}
				if tc.method == http.MethodGet && (!got.endStream || got.dataFrames != 0 || got.lengthHeader != "") {
					t.Errorf("empty GET must end on HEADERS without DATA or content-length")
				}
				if tc.method == http.MethodPost && (got.endStream || got.dataFrames == 0) {
					t.Error("POST body must be sent in DATA frames")
				}
			case <-ctx.Done():
				t.Fatal("upstream request not observed")
			}
			if resp.ProtoMajor != tc.proto || resp.StatusCode != http.StatusOK || string(responseBody) != "accepted" {
				t.Errorf("response=%s/%d body=%q", resp.Proto, resp.StatusCode, responseBody)
			}
			tr.CloseIdleConnections()
			_ = clientConn.Close()
			select {
			case err := <-tunnelDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("intercept tunnel did not end")
			}
		})
	}
}

type interceptUnreadBody struct {
	closed bool
}

func (*interceptUnreadBody) Read([]byte) (int, error) {
	panic("known zero-length body must not be read")
}

func (b *interceptUnreadBody) Close() error {
	b.closed = true
	return nil
}

func TestInterceptHandlerClosesEmptyBodyBeforeRoundTrip(t *testing.T) {
	_, _, cfg, sc, logger, m := testInterceptSetup(t)
	cfg.RequestBodyScanning.Enabled = false
	body := &interceptUnreadBody{}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/payload", nil)
	req.Body = body
	req.GetBody = func() (io.ReadCloser, error) {
		panic("zero-length body must not be restored")
	}
	called := false
	handler := newInterceptHandler(&InterceptContext{
		TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg,
		Scanner: sc, Logger: logger, Metrics: m,
	}, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		if !body.closed || r.Body != nil || r.GetBody != nil {
			t.Errorf("closed=%t Body=%v GetBody absent=%t", body.closed, r.Body, r.GetBody == nil)
		}
		return (&interceptMockRT{body: "accepted", contentType: "text/plain"}).RoundTrip(r)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if !called || w.Code != http.StatusOK {
		t.Fatalf("round trip called=%t status=%d body=%q", called, w.Code, w.Body.String())
	}
}

// Exercise the actual TLS server inside a hijacked CONNECT connection. Its
// net/http handler must turn the abort panic into a TLS close or an h2 reset.
func TestInterceptTunnelStreamIntegrity(t *testing.T) {
	for _, proto := range []int{1, 2} {
		for _, ending := range []string{"chunked_break", "short_length", "cancel", "complete"} {
			t.Run(fmt.Sprintf("h%d/%s", proto, ending), func(t *testing.T) {
				payload := strings.Repeat("intercepted integrity bytes\n", 512)
				release := make(chan struct{})
				var releaseOnce sync.Once
				releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
				upstreamDone := make(chan struct{})
				upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(upstreamDone)
					w.Header().Set("Content-Type", "text/plain")
					if ending == "short_length" {
						w.Header().Set("Content-Length", strconv.Itoa(len(payload)+256))
					}
					_, _ = io.WriteString(w, payload)
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
					if ending == "chunked_break" {
						panic(http.ErrAbortHandler)
					}
				}))
				t.Cleanup(func() { releaseUpstream(); upstream.Close() })
				cache, pool, cfg, _, logger, m := testInterceptSetup(t)
				cfg.FlightRecorder.RequireReceipts = true
				integrityExempt(cfg)
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				rph := newReceiptProxyHelper(t)
				p, err := New(cfg, logger, sc, m, WithReceiptEmitter(rph.emitter))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				u, err := url.Parse(upstream.URL)
				if err != nil {
					t.Fatal(err)
				}
				clientConn, proxyConn := net.Pipe()
				t.Cleanup(func() { _ = clientConn.Close(); _ = proxyConn.Close() })
				tunnelDone := make(chan error, 1)
				go func() {
					tunnelDone <- interceptTunnel(t.Context(), proxyConn, &InterceptContext{
						TargetHost: u.Hostname(), TargetPort: u.Port(), Config: cfg, Scanner: sc,
						CertCache: cache, Logger: logger, Metrics: m, Proxy: p,
						UpstreamRT: upstream.Client().Transport, RequestID: "integrity-tunnel",
					})
				}()
				tr := &http.Transport{
					TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
					ForceAttemptHTTP2: proto == 2,
					DialContext: func(context.Context, string, string) (net.Conn, error) {
						return clientConn, nil
					},
				}
				t.Cleanup(tr.CloseIdleConnections)
				client := &http.Client{Transport: tr}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL+"/payload", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.ProtoMajor != proto || resp.StatusCode != http.StatusOK {
					t.Fatalf("response=%s/%d", resp.Proto, resp.StatusCode)
				}
				first := make([]byte, 1)
				if _, err := io.ReadFull(resp.Body, first); err != nil {
					t.Fatal(err)
				}
				if ending == "cancel" {
					cancel()
				} else {
					releaseUpstream()
				}
				body, readErr := io.ReadAll(resp.Body)
				if ending == "complete" {
					if readErr != nil || string(first)+string(body) != payload {
						t.Fatalf("complete response bytes=%d err=%v", len(body)+1, readErr)
					}
				} else if readErr == nil {
					t.Fatal("intercepted truncated response ended cleanly")
				}
				tr.CloseIdleConnections()
				_ = clientConn.Close()
				select {
				case err := <-tunnelDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("intercept tunnel did not end")
				}
				integrityWait(t, upstreamDone)
				wantReason := httpstream.Incomplete
				if ending == "cancel" {
					wantReason = httpstream.Cancelled
				}
				found := ending == "complete"
				for _, rec := range rph.findReceipts(t) {
					if rec.ActionRecord.Layer == "outcome" && strings.Contains(rec.ActionRecord.Pattern, "reason="+wantReason) {
						found = true
					}
				}
				if !found {
					t.Fatalf("no %s receipt from intercepted stream", wantReason)
				}
			})
		}
	}
}
