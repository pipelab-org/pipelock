// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A credential allowed only at its declared audience still needs a durable
// receipt. Failure must deny before egress and retain the operator's request ID.
func TestBlockReasonRequestIDRequiredReceiptFailures(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportForward, TransportReverse, TransportWS, "intercept", "intercept-without-proxy"} {
		for _, carrier := range []string{"url", "header", "body"} {
			if (transport == TransportFetch || transport == "intercept-without-proxy") && carrier != "url" ||
				transport == TransportWS && carrier == "body" {
				continue
			}
			t.Run(transport+"/"+carrier, func(t *testing.T) {
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.APIAllowlist = nil
				cfg.FlightRecorder.RequireReceipts = true
				cfg.WebSocketProxy.Enabled = true
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
					Name: "test audience credential", Regex: `tstaud-[A-Za-z0-9]{24}`,
					Severity: config.SeverityCritical, CredentialAudienceHosts: []string{"api.vendor.example"},
				})
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				rph := newReceiptProxyHelper(t)
				p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithReceiptEmitter(rph.emitter))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				if err := rph.rec.Close(); err != nil {
					t.Fatal(err)
				}
				credential := "tstaud-" + strings.Repeat("A", 24)
				target := "https://api.vendor.example/resource"
				if carrier == "url" {
					target += "?credential=" + credential
				}
				body := ""
				if carrier == "body" {
					body = `{"credential":"` + credential + `"}`
				}
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(blockreason.HeaderRequestID, "req-999")
				req.Header.Set(blockreason.HeaderOperator, "client command")
				if carrier == "header" {
					req.Header.Set("Authorization", "Bearer "+credential)
				}
				w := httptest.NewRecorder()
				noEgress := capacityRoundTripper(func(*http.Request) (*http.Response, error) {
					t.Error("receipt failure reached upstream")
					return nil, fmt.Errorf("unexpected upstream request")
				})
				p.client.Transport = noEgress
				switch transport {
				case TransportFetch:
					req.Method = http.MethodGet
					req.URL, err = url.Parse("/fetch?url=" + url.QueryEscape(target))
					if err != nil {
						t.Fatal(err)
					}
					p.handleFetch(w, req)
				case TransportForward:
					p.handleForwardHTTP(w, req)
				case TransportReverse:
					upstream, err := url.Parse("https://api.vendor.example")
					if err != nil {
						t.Fatal(err)
					}
					rp := NewReverseProxy(upstream, p.ConfigPtr(), p.ScannerPtr(), p.logger, p.metrics, p.ks, nil, nil)
					rp.SetReceiptEmitter(&p.receiptEmitterPtr)
					rp.proxy.Transport = noEgress
					rp.ServeHTTP(w, req)
				case TransportWS:
					req.Method = http.MethodGet
					wsTarget := strings.Replace(target, "https://", "wss://", 1)
					req.URL, err = url.Parse("/ws?url=" + url.QueryEscape(wsTarget))
					if err != nil {
						t.Fatal(err)
					}
					p.handleWebSocket(w, req)
				default:
					ic := &InterceptContext{
						TargetHost: "api.vendor.example", TargetPort: "443",
						Config: cfg, Scanner: sc, Logger: p.logger, Metrics: p.metrics,
						RequestID: "req-42", ClientIP: "192.0.2.1", Proxy: p,
					}
					if transport == "intercept-without-proxy" {
						ic.Proxy = nil
					}
					req = req.WithContext(context.WithValue(req.Context(), ctxKeyRequestID, "req-888"))
					newInterceptHandler(ic, noEgress).ServeHTTP(w, req)
				}
				if w.Code != http.StatusForbidden ||
					w.Header().Get(blockreason.HeaderReason) != string(blockreason.ReceiptEmissionFailed) {
					t.Fatalf("receipt failure: status=%d reason=%q body=%s", w.Code, w.Header().Get(blockreason.HeaderReason), w.Body.String())
				}
				id := assertBlockRequestID(t, w.Header())
				if strings.HasPrefix(transport, "intercept") && id != "req-42" {
					t.Fatalf("intercept ID = %q, want admitted ID", id)
				}
			})
		}
	}
}

// The budget interface is injected so the same refusal is exercised without
// needing an Enterprise license or spending a live session's budget.
type requestIDDeniedBudget struct {
	*fixedRemainingBudget
}

func (requestIDDeniedBudget) CheckAdmission(string) error {
	return fmt.Errorf("request budget exhausted")
}

func TestBlockReasonRequestIDBudgetAdmission(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportConnect, TransportWS} {
		t.Run(transport, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.APIAllowlist = nil
			cfg.WebSocketProxy.Enabled = true
			p := newTestProxyWithConfig(t, cfg)
			p.editionPtr.Store(&editionSnapshot{fixedBudgetEdition{
				cfg: cfg, sc: p.scannerPtr.Load(), budget: requestIDDeniedBudget{newFixedRemainingBudget(0)},
			}})
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/resource", nil)
			req.Header.Set(blockreason.HeaderRequestID, "req-999")
			w := httptest.NewRecorder()
			switch transport {
			case TransportForward:
				p.handleForwardHTTP(w, req)
			case TransportConnect:
				req.Method = http.MethodConnect
				req.Host = "api.vendor.example:443"
				p.handleConnect(w, req)
			case TransportWS:
				req.URL.RawQuery = "url=wss://api.vendor.example/chat"
				req.URL.Path = "/ws"
				req.URL.Scheme = ""
				req.URL.Host = ""
				p.handleWebSocket(w, req)
			}
			if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "request budget exhausted") {
				t.Fatalf("budget denial: status=%d body=%s", w.Code, w.Body.String())
			}
			assertBlockRequestID(t, w.Header())
		})
	}
}
