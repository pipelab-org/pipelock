// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func sendRawHTTP2Request(t *testing.T, srv *httptest.Server, method, path string, headers, trailers [][2]string, endOnHeaders bool) (int, string) {
	t.Helper()
	tlsCfg := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsCfg.NextProtos = []string{"h2"}
	addr := srv.Listener.Addr().String()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 3 * time.Second},
		Config:    tlsCfg,
	}
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial h2 %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	var hbuf bytes.Buffer
	henc := hpack.NewEncoder(&hbuf)
	for _, kv := range [][2]string{
		{":method", method},
		{":scheme", "https"},
		{":authority", addr},
		{":path", path},
	} {
		if err := henc.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]}); err != nil {
			t.Fatalf("encode pseudo-header %s: %v", kv[0], err)
		}
	}
	for _, kv := range headers {
		if err := henc.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]}); err != nil {
			t.Fatalf("encode header %s: %v", kv[0], err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hbuf.Bytes(),
		EndHeaders:    true,
		EndStream:     endOnHeaders,
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if !endOnHeaders {
		hbuf.Reset()
		for _, kv := range trailers {
			if err := henc.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]}); err != nil {
				t.Fatalf("encode trailer %s: %v", kv[0], err)
			}
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: hbuf.Bytes(),
			EndHeaders:    true,
			EndStream:     true,
		}); err != nil {
			t.Fatalf("write trailers: %v", err)
		}
	}

	var status int
	var body bytes.Buffer
	hdec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			if code, parseErr := strconv.Atoi(f.Value); parseErr == nil {
				status = code
			}
		}
	})
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read h2 frame: %v", err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					t.Fatalf("write settings ack: %v", err)
				}
			}
		case *http2.HeadersFrame:
			if f.StreamID == 1 {
				if _, err := hdec.Write(f.HeaderBlockFragment()); err != nil {
					t.Fatalf("decode response headers: %v", err)
				}
				if f.StreamEnded() {
					return status, body.String()
				}
			}
		case *http2.DataFrame:
			if f.StreamID == 1 {
				body.Write(f.Data())
				if f.StreamEnded() {
					return status, body.String()
				}
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == 1 {
				t.Fatalf("stream reset with %v", f.ErrCode)
			}
		}
	}
}

// TestReverseProxyZeroLengthHTTP2TrailersFailClosed verifies that HTTP/2
// requests declaring trailers with Content-Length: 0 or END_STREAM on HEADERS
// are still rejected by request body scanning rather than skipping scanRequest
// and forwarding unscanned trailer declarations to an HTTP/2 upstream.
func TestReverseProxyZeroLengthHTTP2TrailersFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name         string
		enforce      bool
		method       string
		headers      [][2]string
		trailers     [][2]string
		endOnHeaders bool
		wantStatus   int
		wantHits     int32
	}{
		{
			name:         "content_length_zero_with_trailer_frame",
			enforce:      true,
			method:       http.MethodPost,
			headers:      [][2]string{{"content-length", "0"}, {"trailer", "x-exfil"}},
			trailers:     [][2]string{{"x-exfil", "synthetic-trailer-value"}},
			endOnHeaders: false,
			wantStatus:   http.StatusForbidden,
			wantHits:     0,
		},
		{
			name:         "end_stream_with_declared_trailer",
			enforce:      true,
			method:       http.MethodGet,
			headers:      [][2]string{{"trailer", "x-leak-token"}},
			endOnHeaders: true,
			wantStatus:   http.StatusForbidden,
			wantHits:     0,
		},
		{
			name:         "audit_mode_content_length_zero_with_trailer_frame",
			enforce:      false,
			method:       http.MethodPost,
			headers:      [][2]string{{"content-length", "0"}, {"trailer", "x-exfil"}},
			trailers:     [][2]string{{"x-exfil", "synthetic-trailer-value"}},
			endOnHeaders: false,
			wantStatus:   http.StatusForbidden,
			wantHits:     0,
		},
		{
			name:         "clean_zero_length_without_trailer",
			enforce:      true,
			method:       http.MethodGet,
			endOnHeaders: true,
			wantStatus:   http.StatusOK,
			wantHits:     1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamHits atomic.Int32
			var seenTrailerKeys atomic.Value
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamHits.Add(1)
				keys := make([]string, 0, len(r.Trailer))
				for k := range r.Trailer {
					keys = append(keys, k)
				}
				seenTrailerKeys.Store(keys)
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "ok")
			}))
			upstream.EnableHTTP2 = true
			upstream.StartTLS()
			t.Cleanup(upstream.Close)

			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.Mode = config.ModeBalanced
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.Action = config.ActionBlock
			enforce := tc.enforce
			cfg.Enforce = &enforce
			sc, err := scanner.New(cfg)
			if err != nil {
				t.Fatalf("scanner.New: %v", err)
			}
			t.Cleanup(sc.Close)
			logger, err := audit.New("", "error", "json", false, false)
			if err != nil {
				t.Fatalf("audit.New: %v", err)
			}
			upURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			var cfgPtr atomic.Pointer[config.Config]
			cfgPtr.Store(cfg)
			var scPtr atomic.Pointer[scanner.Scanner]
			scPtr.Store(sc)
			rp := NewReverseProxy(upURL, &cfgPtr, &scPtr, logger, metrics.New(), nil, nil, nil)
			tr := upstream.Client().Transport.(*http.Transport).Clone()
			tr.ForceAttemptHTTP2 = true
			tr.DisableCompression = true
			rp.proxy.Transport = tr

			srv := httptest.NewUnstartedServer(rp)
			srv.EnableHTTP2 = true
			srv.StartTLS()
			t.Cleanup(srv.Close)

			status, body := sendRawHTTP2Request(t, srv, tc.method, "/test", tc.headers, tc.trailers, tc.endOnHeaders)
			if status != tc.wantStatus {
				t.Fatalf("status=%d want %d (body=%q upstreamHits=%d upstreamTrailerKeys=%v)", status, tc.wantStatus, body, upstreamHits.Load(), seenTrailerKeys.Load())
			}
			if got := upstreamHits.Load(); got != tc.wantHits {
				t.Fatalf("upstreamHits=%d want %d (upstreamTrailerKeys=%v)", got, tc.wantHits, seenTrailerKeys.Load())
			}
			if tc.wantStatus == http.StatusForbidden && !strings.Contains(body, "request trailers cannot be scanned") {
				t.Fatalf("block body=%q, want trailer scan failure reason", body)
			}
		})
	}
}
