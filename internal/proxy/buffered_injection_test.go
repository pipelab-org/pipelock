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

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"

	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBufferedCheckerHTTPTransports(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportForward, TransportConnect, TransportReverse} {
		for _, state := range []string{"benign", "finding", "failure", "not_checked"} {
			for _, mode := range []string{config.InjectionModeOff, config.InjectionModeWarn, config.InjectionModeBlock} {
				t.Run(transport+"/"+state+"/"+mode, func(t *testing.T) {
					srv := checkertest.New(t, state)
					cfg := shieldRewriteMarkerConfig()
					cfg.BrowserShield.Enabled = false
					cfg.ResponseScanning.Enabled = true
					cfg.ResponseScanning.Action = config.ActionWarn
					if state == "benign" {
						cfg.ResponseScanning.Action = config.ActionBlock
					}
					srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, mode)
					body := "ordinary upstream content"
					if state == "benign" {
						body = checkertest.Directive
					}
					status, got := requestShieldScan(t, cfg, transport, []byte(body), "text/plain")
					block := mode == config.InjectionModeBlock && state != "benign"
					if (status != http.StatusOK) != block {
						t.Fatalf("status=%d block=%v: %s", status, block, got)
					}
					items := srv.Items()
					if mode == config.InjectionModeOff {
						if len(items) != 0 {
							t.Fatal("off made a request")
						}
						return
					}
					if len(items) != 1 {
						t.Fatalf("checker calls=%d", len(items))
					}
					if items[0].Surface != config.InjectionSurfaceHTTPResponse || items[0].Transport != transport {
						t.Fatalf("item=%+v", items[0])
					}
				})
			}
		}
	}
}

func TestBufferedCheckerShieldTransports(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportForward, TransportConnect, TransportReverse} {
		for _, state := range []string{"benign", "finding", "failure"} {
			t.Run(transport+"/"+state, func(t *testing.T) {
				srv := checkertest.New(t, state)
				cfg := shieldRewriteMarkerConfig()
				enableShieldRewriteMarkerCategories(cfg)
				cfg.BrowserShield.Enabled = true
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.Action = config.ActionWarn
				if state == "benign" {
					cfg.ResponseScanning.Action = config.ActionBlock
				}
				srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeOff)
				srv.Configure(cfg, config.InjectionSurfaceBrowserShield, config.InjectionModeBlock)
				body := `<html><body><article><p>` + strings.Repeat("Ordinary documentation. ", 60) + `</p><div style="display:none">` + checkertest.Directive + `</div></article></body></html>`
				status, got := requestShieldScan(t, cfg, transport, []byte(body), "text/html")
				if (status != http.StatusOK) != (state != "benign") {
					t.Fatalf("status=%d: %s", status, got)
				}
				if len(srv.Items()) != 1 || srv.Items()[0].Surface != config.InjectionSurfaceBrowserShield {
					t.Fatalf("items=%+v", srv.Items())
				}
			})
		}
	}
}

func TestBufferedCheckerRequestBody(t *testing.T) {
	for _, state := range []string{"benign", "finding", "failure", "not_checked"} {
		for _, mode := range []string{config.InjectionModeOff, config.InjectionModeWarn, config.InjectionModeBlock} {
			t.Run(state+"/"+mode, func(t *testing.T) {
				srv := checkertest.New(t, state)
				cfg := testScannerConfig()
				srv.Configure(cfg, config.InjectionSurfaceHTTPRequestBody, mode)
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				text := "ordinary input"
				if state == "benign" {
					text = checkertest.Directive
				}
				_, got := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(`{"message":"` + text + `"}`), ContentType: "application/json", MaxBytes: 1024, Scanner: sc, Action: config.ActionWarn})
				block := mode == config.InjectionModeBlock && state != "benign"
				if (!got.Clean && got.Action == config.ActionBlock) != block {
					t.Fatalf("block=%v result=%+v", block, got)
				}
				if !block && !got.Clean {
					t.Fatalf("non-blocking checker retained wording findings: %+v", got)
				}
				if mode != config.InjectionModeOff && len(srv.Items()) != 1 {
					t.Fatalf("calls=%d", len(srv.Items()))
				}
			})
		}
	}
}

func TestBufferedCheckerRequestTrust(t *testing.T) {
	cfg := testScannerConfig()
	off := false
	cfg.Enforce = &off
	cfg.RequestBodyScanning.TrustedHosts = []string{"api.vendor.example"}
	srv := checkertest.New(t, "finding")
	srv.Configure(cfg, config.InjectionSurfaceHTTPRequestBody, config.InjectionModeBlock)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	assessed := sc.ScanBufferedInjection(t.Context(), scanner.BufferedInjectionScan{Surface: config.InjectionSurfaceHTTPRequestBody, Content: "ordinary input"})
	r := BodyScanResult{InjectionMatches: assessed.Matches}
	if !shouldHardBlockBodyPromptInjection(r, "api.vendor.example", cfg) {
		t.Fatal("explicit external block was reduced by trust or audit mode")
	}
}

func TestBufferedCheckerRequestTransports(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportConnect, TransportReverse} {
		for _, state := range []string{"benign", "finding", "failure", "not_checked"} {
			for _, mode := range []string{config.InjectionModeWarn, config.InjectionModeBlock} {
				t.Run(transport+"/"+state+"/"+mode, func(t *testing.T) {
					srv := checkertest.New(t, state)
					cfg := testScannerConfig()
					cfg.DLP.ScanEnv = false
					disabled := false
					cfg.Enforce = &disabled
					cfg.RequestBodyScanning.Action = config.ActionWarn
					cfg.RequestBodyScanning.TrustedHosts = []string{"api.vendor.example"}
					srv.Configure(cfg, config.InjectionSurfaceHTTPRequestBody, mode)
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					p, err := New(cfg, audit.NewNop(), sc, metrics.New())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(p.Close)
					var hits atomic.Int32
					rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
						hits.Add(1)
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ordinary response")), Request: r}, nil
					})
					p.client.Transport = rt
					text := "ordinary input"
					if state == "benign" {
						text = checkertest.Directive
					}
					req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.vendor.example/notes", strings.NewReader(`{"text":"`+text+`"}`))
					req.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					switch transport {
					case TransportForward:
						p.handleForwardHTTP(w, req)
					case TransportConnect:
						req.URL.Scheme, req.URL.Host = "", ""
						newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: p.logger, Metrics: p.metrics, Proxy: p}, rt).ServeHTTP(w, req)
					case TransportReverse:
						upstream, parseErr := url.Parse("https://api.vendor.example")
						if parseErr != nil {
							t.Fatal(parseErr)
						}
						rp := NewReverseProxy(upstream, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
						rp.proxy.Transport = rt
						rp.ServeHTTP(w, req)
					}
					block := mode == config.InjectionModeBlock && state != "benign"
					if (w.Code != http.StatusOK) != block || (hits.Load() == 0) != block {
						t.Fatalf("status=%d hits=%d block=%v: %s", w.Code, hits.Load(), block, w.Body.String())
					}
					if len(srv.Items()) != 1 {
						t.Fatalf("checker calls=%d", len(srv.Items()))
					}
				})
			}
		}
	}
}

func TestBufferedCheckerStructuredResponse(t *testing.T) {
	for _, state := range []string{"benign", "finding", "failure"} {
		t.Run(state, func(t *testing.T) {
			srv := checkertest.New(t, state)
			cfg := testScannerConfig()
			srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeBlock)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			text := "ordinary structured text"
			if state == "benign" {
				text = checkertest.Directive
			}
			body := []byte(`{"text":"` + text + `","other":"ordinary field"}`)
			view, err := extractStructuredResponse(body)
			if err != nil {
				t.Fatal(err)
			}
			got := scanStructuredResponse(t.Context(), sc, cfg, body, "https://api.vendor.example", view)
			if state == "benign" && (!got.Clean || len(got.Matches) != 0) {
				t.Fatalf("basic wording ran on external structured surface: %+v", got)
			}
			if state == "finding" && !got.CheckerBlocked() {
				t.Fatalf("structured finding lost: %+v", got)
			}
			if state == "failure" && !got.Failed() {
				t.Fatalf("structured failure delivered: %+v", got)
			}
			if len(srv.Items()) != 1 || srv.Items()[0].OriginalBytes != int64(len(body)) {
				t.Fatalf("wrong item: %+v", srv.Items())
			}
		})
	}
}
