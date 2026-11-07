// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testimage"
)

func TestScanRequestBodyBareBase64Images(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	clean := testimage.SmallPNG(t, "")
	key := "AKIA" + "ABCDEFGHIJKLMNOP"
	for _, shape := range []string{"anthropic", "openai", "mcp"} {
		for _, dirty := range []bool{false, true} {
			name := shape + "/clean"
			payload := clean
			if dirty {
				name = shape + "/decoded secret"
				payload = testimage.SmallPNG(t, key)
			}
			t.Run(name, func(t *testing.T) {
				body := testimage.Carrier(t, shape, "png", payload)
				forwarded, r := scanRequestBody(context.Background(), BodyScanRequest{Body: strings.NewReader(body), ContentType: contentTypeJSON, MaxBytes: 1 << 20, Scanner: sc})
				if r.Clean == dirty {
					t.Fatalf("dirty=%v: %+v", dirty, r)
				}
				if r.Clean {
					if string(forwarded) != body {
						t.Fatal("scan view changed delivered bytes")
					}
				}
			})
		}
	}
	for _, tt := range []struct{ name, body string }{
		{"sibling", `{"image":` + testimage.Carrier(t, "anthropic", "png", clean) + `,"key":"` + key + `"}`},
		{"mismatch", testimage.Carrier(t, "anthropic", "jpeg", clean)},
		{"invalid magic", testimage.Carrier(t, "anthropic", "png", []byte(key))},
		{"garbage", `{"media_type":"image/png","data":"` + base64.StdEncoding.EncodeToString(clean) + `!` + key + `"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, r := scanRequestBody(context.Background(), BodyScanRequest{Body: strings.NewReader(tt.body), ContentType: contentTypeJSON, MaxBytes: 1 << 20, Scanner: sc})
			if r.Clean || len(r.DLPMatches) == 0 {
				t.Fatalf("missing DLP finding: %+v", r)
			}
		})
	}
}

func TestBareBase64ImageHTTPTransports(t *testing.T) {
	for _, transport := range []string{"forward", "intercept"} {
		for _, shape := range []string{"anthropic", "openai"} {
			for _, dirty := range []bool{false, true} {
				name := transport + "/" + shape + "/image"
				if dirty {
					name += " with sibling key"
				}
				t.Run(name, func(t *testing.T) {
					body := testimage.Carrier(t, shape, "png", testimage.SmallPNG(t, ""))
					if dirty {
						body = `{"image":` + body + `,"credential":"` + "AKIA" + "ABCDEFGHIJKLMNOP" + `"}`
					}
					var hits atomic.Int32
					received := make(chan string, 1)
					handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						b, err := io.ReadAll(r.Body)
						if err != nil {
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						hits.Add(1)
						received <- string(b)
						_, _ = w.Write([]byte("ok"))
					})
					upstream := httptest.NewUnstartedServer(handler)
					if transport == "intercept" {
						upstream.StartTLS()
					} else {
						upstream.Start()
					}
					defer upstream.Close()
					req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL+"/images", strings.NewReader(body))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Content-Type", contentTypeJSON)
					var resp *http.Response
					if transport == "intercept" {
						cache, pool, cfg, _, logger, m := testInterceptSetup(t)
						cfg.RequestBodyScanning.Enabled = true
						cfg.RequestBodyScanning.Action = config.ActionBlock
						cfg.DLP.ScanEnv = false
						sc := scanner.MustNew(cfg)
						defer sc.Close()
						resp = interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, m, req)
					} else {
						addr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
							cfg.RequestBodyScanning.Enabled = true
							cfg.RequestBodyScanning.Action = config.ActionBlock
							cfg.DLP.ScanEnv = false
						})
						defer cleanup()
						resp, err = forwardHTTPClient(t, addr).Do(req)
						if err != nil {
							t.Fatal(err)
						}
					}
					defer func() { _ = resp.Body.Close() }()
					want := http.StatusOK
					if dirty {
						want = http.StatusForbidden
					}
					if resp.StatusCode != want {
						t.Fatalf("status=%d want %d", resp.StatusCode, want)
					}
					if dirty {
						if hits.Load() != 0 {
							t.Fatal("credential reached recipient")
						}
						return
					}
					select {
					case got := <-received:
						if got != body {
							t.Fatal("recipient bytes changed")
						}
					default:
						t.Fatal("image never reached recipient")
					}
				})
			}
		}
	}
}
