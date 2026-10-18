// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const withheldFieldEvent = "withheld-field-event"

func fieldLimitSSEBody() string {
	var body strings.Builder
	body.WriteString("data: {\"text\":\"first-event\"}\n\ndata: {\"text\":\"" + withheldFieldEvent + "\"")
	for i := range extract.FieldTailFrameMaxLeaves {
		_, _ = fmt.Fprintf(&body, ",\"f%d\":\"value\"", i)
	}
	body.WriteString("}\n\n")
	return body.String()
}

func requireFieldLimitBlockReceipt(t *testing.T, receipts []receipt.Receipt) {
	t.Helper()
	found := false
	for _, r := range receipts {
		if r.ActionRecord.Layer == "response_scan_error" {
			found = true
			if r.ActionRecord.Verdict != config.ActionBlock {
				t.Errorf("inspection verdict = %q, want block", r.ActionRecord.Verdict)
			}
		}
		if r.ActionRecord.Verdict == config.ActionAllow && r.ActionRecord.DecisionPhase != receipt.DecisionPhaseIntent {
			t.Errorf("incomplete stream emitted allow receipt: %+v", r.ActionRecord)
		}
		if r.ActionRecord.Layer == LayerSSEStream || r.ActionRecord.Layer == LayerA2AStream {
			t.Errorf("field limit classified as a content finding: %+v", r.ActionRecord)
		}
	}
	if !found {
		t.Fatal("missing response_scan_error receipt")
	}
}

func TestInterceptSSEFieldLimitRecordsIncompleteOutcome(t *testing.T) {
	for _, a2a := range []bool{false, true} {
		for _, action := range []string{config.ActionBlock, config.ActionWarn} {
			for _, exempt := range []bool{false, true} {
				t.Run(fmt.Sprintf("a2a=%v/action=%s/exempt=%v", a2a, action, exempt), func(t *testing.T) {
					cache, pool, cfg, _, logger, m := testInterceptSetup(t)
					cfg.ResponseScanning.SSEStreaming.Enabled = true
					cfg.ResponseScanning.SSEStreaming.Action = action
					cfg.A2AScanning.Enabled = a2a
					cfg.A2AScanning.Action = action
					if exempt {
						cfg.ResponseScanning.ExemptDomains = []string{testLoopbackIP}
					}
					cfg.FlightRecorder.RequireReceipts = true
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					p, err := New(cfg, logger, sc, m)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(p.Close)
					rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
					p.receiptEmitterPtr.Store(rph.emitter)
					rt := roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
							Body:       io.NopCloser(strings.NewReader(fieldLimitSSEBody())),
						}, nil
					})
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+net.JoinHostPort(testLoopbackIP, "9999")+"/events", nil)
					if err != nil {
						t.Fatal(err)
					}
					if a2a {
						req.Header.Set("Content-Type", "application/a2a+json")
					}
					resp := interceptWithRT(t, cache, pool, cfg, sc, logger, m, rt, &InterceptContext{Proxy: p, TargetHost: testLoopbackIP, TargetPort: "9999"}, req)
					body, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if !strings.Contains(string(body), "first-event") || strings.Contains(string(body), withheldFieldEvent) {
						t.Errorf("stream delivery = %q", body)
					}
					requireFieldLimitBlockReceipt(t, rph.findReceipts(t))
				})
			}
		}
	}
}

func TestForwardAndReverseSSEFieldLimitRecordsIncompleteOutcome(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportReverse} {
		for _, a2a := range []bool{false, true} {
			if transport == TransportReverse && a2a {
				continue // Reverse responses use the generic SSE scanner.
			}
			for _, action := range []string{config.ActionBlock, config.ActionWarn} {
				t.Run(fmt.Sprintf("%s/a2a=%v/action=%s", transport, a2a, action), func(t *testing.T) {
					configure := func(cfg *config.Config) {
						cfg.ForwardProxy.Enabled = true
						cfg.ResponseScanning.SSEStreaming.Enabled = true
						cfg.ResponseScanning.SSEStreaming.Action = action
						cfg.A2AScanning.Enabled = a2a
						cfg.A2AScanning.Action = action
					}
					upstream := func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, fieldLimitSSEBody())
					}
					var target string
					var client *http.Client
					var collect func() []receipt.Receipt
					if transport == TransportReverse {
						cfg := reverseTestConfig()
						configure(cfg)
						srv, dir, closeRecorder := reverseReceiptParitySetup(t, cfg, upstream)
						target, client = srv.URL+"/events", srv.Client()
						collect = func() []receipt.Receipt {
							waitForReceiptOrTimeout(t, dir)
							closeRecorder()
							return extractReceiptsFromDir(t, dir)
						}
					} else {
						backend := httptest.NewServer(http.HandlerFunc(upstream))
						t.Cleanup(backend.Close)
						rph := newReceiptProxyHelper(t)
						proxy := httptest.NewServer(setupFetchProxyWithReceipts(t, rph, configure))
						t.Cleanup(proxy.Close)
						proxyURL, err := url.Parse(proxy.URL)
						if err != nil {
							t.Fatal(err)
						}
						tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
						t.Cleanup(tr.CloseIdleConnections)
						target, client = backend.URL+"/events", &http.Client{Transport: tr}
						collect = func() []receipt.Receipt { return rph.findReceipts(t) }
					}
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
					if err != nil {
						t.Fatal(err)
					}
					if a2a {
						req.Header.Set("Content-Type", "application/a2a+json")
					}
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					body, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if !strings.Contains(string(body), "first-event") || strings.Contains(string(body), withheldFieldEvent) {
						t.Errorf("stream delivery = %q", body)
					}
					requireFieldLimitBlockReceipt(t, collect())
				})
			}
		}
	}
}
