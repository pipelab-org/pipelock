// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBodyParseFailureIdentity(t *testing.T) {
	cases := []struct{ name, contentType, body string }{
		{"JSON", "application/json", `{"jsonrpc":"2.0","method":"message/send","params":`},
		{"form", "application/x-www-form-urlencoded", "field=%zz"},
		{"multipart", "multipart/form-data; boundary=B", "--B\r\nContent-Disposition: form-data; name=field\r\n\r\ntext"},
		{"missing boundary", "multipart/form-data", "text"},
	}
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		for _, policy := range []uploadPolicy{{config.ActionBlock, false}, {config.ActionWarn, false}, {config.ActionWarn, true}} {
			h := newUploadHarness(t, surface, policy)
			for _, tc := range cases {
				t.Run(fmt.Sprintf("%s/%s/%t/%s", surface, policy.action, policy.audit, tc.name), func(t *testing.T) {
					status, hits, _, message, hdr := h.exercise(t, http.Header{"Content-Type": {tc.contentType}}, []byte(tc.body))
					if status != http.StatusForbidden || hits != 0 || hdr.Get("X-Pipelock-Block-Reason") != "parse_error" || hdr.Get("X-Pipelock-Block-Reason-Layer") != scanner.ScannerParser {
						t.Fatalf("status=%d hits=%d headers=%v body=%s", status, hits, hdr, message)
					}
					if hint := hdr.Get("X-Pipelock-Hint"); !strings.Contains(hint, "input could not be parsed or fully scanned") || strings.Contains(hint, "secret") {
						t.Fatalf("hint=%q", hint)
					}
				})
			}
			status, hits, intact, message, _ := h.exercise(t, http.Header{"Content-Type": {"application/json"}}, []byte(`{"message":"ordinary text"}`))
			if status != http.StatusCreated || hits != 1 || !intact {
				t.Fatalf("valid control: status=%d hits=%d intact=%t body=%s", status, hits, intact, message)
			}
		}
	}
}

func TestWebSocketTargetURLLength(t *testing.T) {
	backend, closeBackend := wsEchoServer(t)
	defer closeBackend()
	const limit = 160
	cfg := testScannerConfig()
	cfg.WebSocketProxy.Enabled = true
	cfg.FetchProxy.Monitoring.MaxURLLength = limit
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	p := newTestProxyWithConfig(t, cfg)
	server := httptest.NewServer(p.Handler())
	defer server.Close()
	for _, delta := range []int{-1, 0, 1} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			base := "ws://" + backend + "/"
			target := base + strings.Repeat("a", limit+delta-len(base))
			conn, err := dialWSConnToTarget(strings.TrimPrefix(server.URL, "http://"), target)
			if delta <= 0 {
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.Close()
				return
			}
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil {
				t.Fatal("over-limit target accepted")
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ws?url="+url.QueryEscape(target), nil)
			rec := httptest.NewRecorder()
			p.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || rec.Header().Get("X-Pipelock-Block-Reason") != "url_length" {
				t.Fatalf("status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body)
			}
		})
	}
}

func TestBodyParseFailureReceipts(t *testing.T) {
	for _, surface := range []string{"forward", "intercept", "websocket"} {
		for _, scanFailure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/scan_failure=%t", surface, scanFailure), func(t *testing.T) {
				cfg := testScannerConfig()
				cfg.AdaptiveEnforcement.Enabled = false
				cfg.RequestBodyScanning.Action = config.ActionWarn
				enforce := false
				cfg.Enforce = &enforce
				p := newTestProxyWithConfig(t, cfg)
				rph := newReceiptProxyHelper(t)
				p.receiptEmitterPtr.Store(rph.emitter)
				sc := p.scannerPtr.Load()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var input io.Reader = strings.NewReader(`{"incomplete":`)
				wantLayer, wantPattern := scanner.ScannerParser, "decoding JSON body"
				if scanFailure {
					input = &cancelAfterFirstResponseRead{Reader: strings.NewReader(`{"message":"ordinary text"}`), cancel: cancel}
					wantLayer, wantPattern = scanner.ScannerContext, "request body scan failed:"
				}

				if surface == "websocket" {
					relay := &wsRelay{clientConn: discardConn{}, upstreamConn: discardConn{}, proxy: p, cfg: cfg, hostname: "api.vendor.example", targetURL: "wss://api.vendor.example/socket"}
					body, result := scanRequestBody(ctx, BodyScanRequest{Body: input, ContentType: "application/json", MaxBytes: 1024, Scanner: sc, Action: config.ActionWarn})
					if !relay.handleClientMessageBodyResult(audit.NewNop(), body, result) {
						t.Fatal("malformed frame allowed")
					}
				} else {
					req := httptest.NewRequestWithContext(ctx, http.MethodPost, "http://api.vendor.example/submit", input)
					req.Header.Set("Content-Type", "application/json")
					rec := httptest.NewRecorder()
					if surface == "forward" {
						p.handleForwardHTTP(rec, req)
					} else {
						handler := newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New(), Proxy: p}, http.DefaultTransport)
						handler.ServeHTTP(rec, req)
					}
					if rec.Code != http.StatusForbidden {
						t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
					}
					if rec.Header().Get("X-Pipelock-Block-Reason") != "parse_error" || rec.Header().Get("X-Pipelock-Block-Reason-Layer") != wantLayer {
						t.Fatalf("headers=%v, want fail-closed layer %s", rec.Header(), wantLayer)
					}
				}
				got := rph.requireReceipt(t, wantLayer).ActionRecord
				if got.Verdict != config.ActionBlock || !strings.Contains(got.Pattern, wantPattern) || strings.Contains(got.Pattern, "secret") {
					t.Fatalf("receipt=%+v", got)
				}
			})
		}
	}
}

func TestBodyParseFailureReverseReceipt(t *testing.T) {
	for _, scanFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(scanFailure), func(t *testing.T) {
			cfg := reverseParityBaseConfig(t)
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.Action = config.ActionWarn
			enforce := false
			cfg.Enforce = &enforce
			cfg.AdaptiveEnforcement.Enabled = false
			rp, _, _, dir, closeRecorder, key := newReverseParityHarnessWithReceipts(t, cfg, func(_ http.ResponseWriter, _ *http.Request) { t.Error("malformed body reached upstream") })

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var input io.Reader = strings.NewReader(`{"incomplete":`)
			wantLayer, wantPattern := scanner.ScannerParser, "decoding JSON body"
			if scanFailure {
				input = &cancelAfterFirstResponseRead{Reader: strings.NewReader(`{"message":"ordinary text"}`), cancel: cancel}
				wantLayer, wantPattern = scanner.ScannerContext, "request body scan failed:"
			}

			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "http://proxy.vendor.example/submit", input)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
			}
			if rec.Header().Get("X-Pipelock-Block-Reason") != "parse_error" || rec.Header().Get("X-Pipelock-Block-Reason-Layer") != wantLayer {
				t.Fatalf("headers=%v, want fail-closed layer %s", rec.Header(), wantLayer)
			}
			closeRecorder()
			for _, got := range extractReceiptsFromDir(t, dir) {
				if got.ActionRecord.Layer == wantLayer {
					if got.ActionRecord.Verdict != config.ActionBlock || !strings.Contains(got.ActionRecord.Pattern, wantPattern) {
						t.Fatalf("receipt=%+v", got.ActionRecord)
					}
					if err := receipt.VerifyWithKey(got, hex.EncodeToString(key)); err != nil {
						t.Fatal(err)
					}
					return
				}
			}
			t.Fatal("no parser receipt")
		})
	}
}
