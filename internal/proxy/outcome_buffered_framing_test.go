// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const bufferedFramingBody = "ordinary response"

func TestBufferedOutcomeFraming(t *testing.T) {
	for _, surface := range []string{"reverse", "reverse_strip", "forward_scanned", "forward_scanned_strip", "forward_core", "intercept", "intercept_strip"} {
		for _, trailer := range []string{"none", "declared", "unannounced"} {
			t.Run(surface+"/"+trailer, func(t *testing.T) {
				baseSurface := strings.TrimSuffix(surface, "_strip")
				wantBody := bufferedFramingBody
				configureStrip := func(cfg *config.Config) {
					if baseSurface != surface {
						cfg.ResponseScanning.Action = config.ActionStrip
						cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "framing marker", Regex: "ordinary"}}
						wantBody = "[REDACTED: framing marker] response"
					}
				}
				upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					if trailer == "declared" {
						w.Header().Set("Trailer", "X-Checksum")
					}
					// Unknown-length upstream responses exercise the synthesized length.
					w.(http.Flusher).Flush()
					_, _ = io.WriteString(w, bufferedFramingBody)
					switch trailer {
					case "declared":
						w.Header().Set("X-Checksum", "checked")
					case "unannounced":
						w.Header().Set(http.TrailerPrefix+"X-Checksum", "checked")
					}
				})
				rph := newReceiptProxyHelper(t)
				t.Cleanup(func() { _ = rph.rec.Close() })
				if baseSurface == "intercept" {
					upstream := httptest.NewTLSServer(upstreamHandler)
					t.Cleanup(upstream.Close)
					cache, pool, cfg, _, logger, m := testInterceptSetup(t)
					cfg.FlightRecorder.RequireReceipts = true
					cfg.ResponseScanning.Enabled = true
					configureStrip(cfg)
					sc := scanner.MustNew(cfg)
					p, err := New(cfg, logger, sc, m, WithReceiptEmitter(rph.emitter))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(p.Close)
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
					if err != nil {
						t.Fatal(err)
					}
					resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, p)
					defer func() { _ = resp.Body.Close() }()
					requireBufferedOutcomeFraming(t, resp, trailer, false, wantBody)
					return
				}

				upstream := httptest.NewServer(upstreamHandler)
				t.Cleanup(upstream.Close)
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
				cfg.APIAllowlist = nil
				cfg.ForwardProxy.Enabled = true
				cfg.FlightRecorder.RequireReceipts = true
				cfg.ResponseScanning.Enabled = baseSurface != "forward_core"
				configureStrip(cfg)
				if baseSurface == "forward_core" {
					cfg.MediaPolicy.Enabled = ptrBool(false)
				}
				sc := scanner.MustNew(cfg)
				p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithReceiptEmitter(rph.emitter))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				handler := p.buildHandler(p.buildMux())
				if baseSurface == "reverse" {
					u, parseErr := url.Parse(upstream.URL)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					var cfgPtr atomic.Pointer[config.Config]
					var scPtr atomic.Pointer[scanner.Scanner]
					cfgPtr.Store(cfg)
					scPtr.Store(sc)
					rp := NewReverseProxy(u, &cfgPtr, &scPtr, p.logger, p.metrics, killswitch.New(cfg), nil, nil)
					rp.SetReceiptEmitter(&p.receiptEmitterPtr)
					handler = rp
				}
				srv := httptest.NewServer(handler)
				t.Cleanup(srv.Close)
				client := srv.Client()
				client.Timeout = 5 * time.Second
				target := srv.URL
				if strings.HasPrefix(surface, "forward_") {
					proxyURL, parseErr := url.Parse(srv.URL)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
					t.Cleanup(transport.CloseIdleConnections)
					client = &http.Client{Transport: transport, Timeout: 5 * time.Second}
					target = upstream.URL
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				requireBufferedOutcomeFraming(t, resp, trailer, baseSurface == "reverse", wantBody)
			})
		}
	}
}

func requireBufferedOutcomeFraming(t *testing.T, resp *http.Response, trailer string, relaysTrailers bool, wantBody string) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != wantBody {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}
	if trailer == "none" {
		if resp.ContentLength != int64(len(body)) || len(resp.TransferEncoding) != 0 {
			t.Errorf("no-trailer framing: length=%d encoding=%v, want exact length %d", resp.ContentLength, resp.TransferEncoding, len(body))
		}
		return
	}
	if resp.Header.Get("Content-Length") != "" || resp.ContentLength != -1 {
		t.Errorf("trailer response has explicit length: header=%q length=%d", resp.Header.Get("Content-Length"), resp.ContentLength)
	}
	if relaysTrailers {
		if got := resp.Trailer.Get("X-Checksum"); got != "checked" {
			t.Errorf("trailer X-Checksum = %q, want checked", got)
		}
	} else if len(resp.Trailer) != 0 {
		// Forward and intercept discard upstream trailers; framing must not
		// expand which trailers those paths relay.
		t.Errorf("unexpected relayed trailers: %v", resp.Trailer)
	}
}

func TestBufferedOutcomeFramingTrailerAnnouncement(t *testing.T) {
	for _, trailer := range []string{"map", "header"} {
		t.Run(trailer, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.FlightRecorder.RequireReceipts = true
			resp := &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header),
				TransferEncoding: []string{"chunked"},
				Request:          httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/data", nil),
			}
			if trailer == "map" {
				resp.Trailer = http.Header{"X-Checksum": nil}
			} else {
				resp.Header.Set("Trailer", "X-Checksum")
			}
			setBufferedReverseResponseBody(resp, []byte(bufferedFramingBody), cfg)
			if resp.Header.Get("Content-Length") != "" || len(resp.TransferEncoding) != 1 || resp.TransferEncoding[0] != "chunked" {
				t.Fatalf("trailer framing changed: headers=%v encoding=%v", resp.Header, resp.TransferEncoding)
			}
		})
	}
}
