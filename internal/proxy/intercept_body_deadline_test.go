// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestInterceptBodyReadDeadline(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%t", h2), func(t *testing.T) {
			seen := make(chan int, 1)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.ProtoMajor
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Length", "20")
				_, _ = io.WriteString(w, "abc")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			origin.EnableHTTP2 = h2
			origin.StartTLS()
			defer origin.Close()
			upstreamRoots := x509.NewCertPool()
			upstreamRoots.AddCert(origin.Certificate())
			addr, roots, cleanup := setupForwardProxyWithTLS(t, func(cfg *config.Config) {
				cfg.FetchProxy.TimeoutSeconds = 1
				cfg.ForwardProxy.IdleTimeoutSeconds = 60
				cfg.ForwardProxy.MaxTunnelSeconds = 60
			}, upstreamRoots)
			defer cleanup()
			proxyURL, err := url.Parse("http://" + addr)
			if err != nil {
				t.Fatal(err)
			}
			tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: h2}
			defer tr.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL+"/stall", nil)
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			resp, err := (&http.Client{Transport: tr}).Do(req)
			if err != nil {
				select {
				case proto := <-seen:
					t.Logf("origin sent headers and partial body over HTTP/%d", proto)
				default:
					t.Fatal("control did not reach the stalled origin body")
				}
				t.Fatalf("upstream stall was not refused before client cancellation: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "response read error") {
				t.Fatalf("status=%d body=%q", resp.StatusCode, b)
			}
			wantProto := 1
			if h2 {
				wantProto = 2
			}
			if got := <-seen; got != wantProto || resp.ProtoMajor != wantProto {
				t.Fatalf("origin proto=%d downstream proto=%d want=%d", got, resp.ProtoMajor, wantProto)
			}
			t.Logf("status=%d protocol=%d elapsed=%s body=%s", resp.StatusCode, resp.ProtoMajor, time.Since(started), b)
		})
	}
}

// A progressing response may legitimately take longer than the fetch timeout.
// This is the compatibility boundary between an idle bound and a total timer.
func TestInterceptBodyReadProgress(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%t", h2), func(t *testing.T) {
			const timeout = time.Second
			const chunks = 6
			stallEntered := make(chan string, 1)
			progressPeer := make(chan string, 1)
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/stall" {
					w.Header().Set("Content-Type", "text/plain")
					w.Header().Set("Content-Length", "20")
					_, _ = io.WriteString(w, "abc")
					w.(http.Flusher).Flush()
					stallEntered <- r.RemoteAddr
					<-r.Context().Done()
					return
				}
				progressPeer <- r.RemoteAddr
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Length", "6")
				tick := time.NewTicker(timeout / 4)
				defer tick.Stop()
				for i := 0; i < chunks; i++ {
					if i > 0 {
						select {
						case <-tick.C:
						case <-r.Context().Done():
							return
						}
					}
					_, _ = io.WriteString(w, "a")
					w.(http.Flusher).Flush()
				}
			}))
			origin.EnableHTTP2 = h2
			origin.StartTLS()
			defer origin.Close()
			upstreamRoots := x509.NewCertPool()
			upstreamRoots.AddCert(origin.Certificate())
			addr, roots, cleanup := setupForwardProxyWithTLS(t, func(cfg *config.Config) {
				cfg.FetchProxy.TimeoutSeconds = 1
				cfg.ForwardProxy.IdleTimeoutSeconds = 60
				cfg.ForwardProxy.MaxTunnelSeconds = 60
			}, upstreamRoots)
			defer cleanup()
			proxyURL, err := url.Parse("http://" + addr)
			if err != nil {
				t.Fatal(err)
			}
			tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: h2, MaxConnsPerHost: 1}
			defer tr.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(t.Context(), 8*timeout)
			defer cancel()
			client := &http.Client{Transport: tr, Timeout: 8 * timeout}
			stallDone := make(chan error, 1)
			var stalledPeer string
			if h2 {
				stallReq, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL+"/stall", nil)
				if err != nil {
					t.Fatal(err)
				}
				go func() {
					resp, err := client.Do(stallReq)
					if err == nil {
						_, err = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
						if resp.StatusCode != http.StatusForbidden {
							err = fmt.Errorf("stalled stream status=%d", resp.StatusCode)
						}
					}
					stallDone <- err
				}()
				select {
				case stalledPeer = <-stallEntered:
				case <-ctx.Done():
					t.Fatal("stalled HTTP/2 stream never reached origin")
				}
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL+"/progress", nil)
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != http.StatusOK || string(body) != strings.Repeat("a", chunks) {
				t.Fatalf("progressing body status=%d body=%q err=%v", resp.StatusCode, body, err)
			}
			if elapsed := time.Since(started); elapsed <= timeout {
				t.Fatalf("control did not cross total timeout: %s", elapsed)
			}
			peer := <-progressPeer
			if h2 {
				if peer != stalledPeer {
					t.Fatalf("HTTP/2 requests did not share an upstream connection: %s != %s", peer, stalledPeer)
				}
				if err := <-stallDone; err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("progressing response completed after %s", time.Since(started))
		})
	}
}

// Fetch and plain forward requests retain their existing total-call timeout.
func TestInterceptBodyReadPeerTransports(t *testing.T) {
	for _, transport := range []string{"fetch", "forward"} {
		t.Run(transport, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			origin := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Length", "20")
				_, _ = io.WriteString(w, "abc")
				w.(http.Flusher).Flush()
				entered <- struct{}{}
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			defer origin.Close()
			defer close(release)
			configure := func(cfg *config.Config) { cfg.FetchProxy.TimeoutSeconds = 1 }
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			var status int
			var body []byte
			if transport == "fetch" {
				p, _ := fetchRequireReceiptsLiveProxy(t, configure)
				defer p.Close()
				rec := httptest.NewRecorder()
				p.handleFetch(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, "/fetch?url="+url.QueryEscape(origin.URL), nil))
				status, body = rec.Code, rec.Body.Bytes()
				if status != http.StatusBadGateway || !strings.Contains(string(body), "reading response") {
					t.Fatalf("fetch status=%d body=%s", status, body)
				}
			} else {
				addr, cleanup := setupForwardProxy(t, configure)
				defer cleanup()
				proxyURL, err := url.Parse("http://" + addr)
				if err != nil {
					t.Fatal(err)
				}
				tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
				defer tr.CloseIdleConnections()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := (&http.Client{Transport: tr}).Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				body, err = io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				status = resp.StatusCode
				if status != http.StatusForbidden || !strings.Contains(string(body), "response read error") {
					t.Fatalf("forward status=%d body=%s", status, body)
				}
			}
			select {
			case <-entered:
			default:
				t.Fatal("origin body was not reached")
			}
			if ctx.Err() != nil {
				t.Fatalf("caller timeout ended the control instead: %v", ctx.Err())
			}
			t.Logf("%s retained its total-call timeout: status=%d", transport, status)
		})
	}
}

// The idle window measures upstream silence only. A client that pauses
// reading longer than the window blocks the proxy's downstream writes while
// the upstream stays ready; that pause must not be counted as an upstream
// stall and sever the download.
func TestInterceptBodyReadDownstreamPause(t *testing.T) {
	const size = 24 << 20
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(size))
		for i := 0; i < size/len(chunk); i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	origin.StartTLS()
	defer origin.Close()
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(origin.Certificate())
	addr, roots, cleanup := setupForwardProxyWithTLS(t, func(cfg *config.Config) {
		cfg.FetchProxy.TimeoutSeconds = 1
		cfg.ForwardProxy.IdleTimeoutSeconds = 60
		cfg.ForwardProxy.MaxTunnelSeconds = 60
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.ExemptDomains = []string{"127.0.0.1"}
	}, upstreamRoots)
	defer cleanup()
	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL+"/large", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	first := make([]byte, 1024)
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	// Pause well past the one-second window so the proxy's writes block.
	pause := time.NewTimer(2500 * time.Millisecond)
	defer pause.Stop()
	<-pause.C
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || n+int64(len(first)) != size {
		t.Fatalf("download cut after a downstream pause: status=%d read=%d want=%d err=%v", resp.StatusCode, n+int64(len(first)), size, err)
	}
}
