// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestAuditModeA2ARefusals records A2A scanning with enforce false and with
// ordinary request and response body scanning turned off, so the A2A scanner
// is the subject. A core credential and an incomplete nested body stay
// refused. A blocklisted URL inside the A2A body or extension header is
// delivered. On the forward path a refusal increments pipelock_requests_total
// and writes a block receipt. The forward response and header refusals log
// anomaly. On the intercept path the same refusals log blocked and
// intercept_http, increment the TLS block counter, and write a block receipt.
func TestAuditModeA2ARefusals(t *testing.T) {
	core := auditFloorValue("core")
	benign := `{"text":"hello"}`
	deep := nestedAuditPayload(70)
	policy := `{"url":"https://blocked.example/message"}`
	forwardRefused := auditModeObservation{status: http.StatusForbidden, events: "blocked", blockMetrics: "pipelock_requests_total", blockReceipt: true}
	forwardResponseRefused := auditModeObservation{status: http.StatusForbidden, upstream: 1, events: "anomaly", blockMetrics: "pipelock_requests_total", blockReceipt: true}
	forwardHeaderRefused := auditModeObservation{status: http.StatusForbidden, events: "anomaly", blockMetrics: "pipelock_requests_total", blockReceipt: true}
	forwardReleased := auditModeObservation{status: http.StatusOK, delivered: true, upstream: 1, events: "anomaly,forward_http"}
	interceptRequestRefused := auditModeObservation{status: http.StatusForbidden, events: "blocked,intercept_http", blockMetrics: "pipelock_tls_request_blocked_total", blockReceipt: true}
	interceptResponseRefused := auditModeObservation{status: http.StatusForbidden, upstream: 1, events: "blocked,intercept_http", blockMetrics: "pipelock_tls_response_blocked_total", blockReceipt: true}
	interceptReleased := auditModeObservation{status: http.StatusOK, delivered: true, upstream: 1, events: "anomaly,intercept_http"}
	cases := []struct {
		name, transport, direction, request, response, header string
		want                                                  auditModeObservation
	}{
		{name: "forward request core", transport: "forward", direction: "request", request: `{"token":"` + core + `"}`, response: benign, want: forwardRefused},
		{name: "forward request policy", transport: "forward", direction: "request", request: policy, response: benign, want: forwardReleased},
		{name: "forward request incomplete", transport: "forward", direction: "request", request: deep, response: benign, want: forwardRefused},
		{name: "forward response core", transport: "forward", direction: "response", request: benign, response: `{"token":"` + core + `"}`, want: forwardResponseRefused},
		{name: "forward response policy", transport: "forward", direction: "response", request: benign, response: policy, want: forwardReleased},
		{name: "forward response incomplete", transport: "forward", direction: "response", request: benign, response: deep, want: forwardResponseRefused},
		{name: "forward header core", transport: "forward", direction: "header", header: "https://ext.example/v1?token=" + core, want: forwardHeaderRefused},
		{name: "forward header policy", transport: "forward", direction: "header", header: "https://blocked.example/v1", want: forwardReleased},
		{name: "intercept request core", transport: "intercept", direction: "request", request: `{"token":"` + core + `"}`, response: benign, want: interceptRequestRefused},
		{name: "intercept request policy", transport: "intercept", direction: "request", request: policy, response: benign, want: interceptReleased},
		{name: "intercept request incomplete", transport: "intercept", direction: "request", request: deep, response: benign, want: interceptRequestRefused},
		{name: "intercept response core", transport: "intercept", direction: "response", request: benign, response: `{"token":"` + core + `"}`, want: interceptResponseRefused},
		{name: "intercept response policy", transport: "intercept", direction: "response", request: benign, response: policy, want: interceptReleased},
		{name: "intercept response incomplete", transport: "intercept", direction: "response", request: benign, response: deep, want: interceptResponseRefused},
		{name: "intercept header core", transport: "intercept", direction: "header", header: "https://ext.example/v1?token=" + core, want: interceptRequestRefused},
		{name: "intercept header policy", transport: "intercept", direction: "header", header: "https://blocked.example/v1", want: interceptReleased},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			rig := newAuditModeRig(t, func(cfg *config.Config) {
				cfg.A2AScanning.Enabled = true
				cfg.A2AScanning.Action = config.ActionBlock
				cfg.RequestBodyScanning.Enabled = false
				cfg.ResponseScanning.Enabled = false
				cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.example"}
			})
			w := httptest.NewRecorder()
			request := tc.request
			if request == "" {
				request = benign
			}
			response := tc.response
			if response == "" {
				response = benign
			}
			if tc.transport == "forward" {
				upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					hits.Add(1)
					w.Header().Set("Content-Type", "application/a2a+json")
					_, _ = io.WriteString(w, response)
				}))
				t.Cleanup(upstream.Close)
				req := newA2AForwardBodyRequest(t, upstream.URL+"/message:send", request)
				if tc.header != "" {
					req.Header.Set("A2A-Extensions", tc.header)
				}
				rig.proxy.handleForwardHTTP(w, req)
			} else {
				handler := newInterceptHandler(&InterceptContext{
					TargetHost: "peer.example", TargetPort: "443", Config: rig.proxy.cfgPtr.Load(),
					Scanner: rig.proxy.scannerPtr.Load(), Logger: rig.proxy.logger, Metrics: rig.proxy.metrics,
					ClientIP: testLoopbackIP, RequestID: "audit-mode-a2a", Agent: agentAnonymous,
					Proxy: rig.proxy,
				}, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					hits.Add(1)
					return &http.Response{
						StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/a2a+json"}},
						Body: io.NopCloser(strings.NewReader(response)), ContentLength: int64(len(response)), Request: r,
					}, nil
				}))
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://peer.example/message:send", strings.NewReader(request))
				req.Header.Set("Content-Type", "application/a2a+json")
				if tc.header != "" {
					req.Header.Set("A2A-Extensions", tc.header)
				}
				handler.ServeHTTP(w, req)
			}
			delivered := w.Code == http.StatusOK && !strings.Contains(w.Body.String(), `"blocked":true`)
			assertAuditMode(t, rig.observation(t, w.Code, delivered, hits.Load()), tc.want)
		})
	}
}

func nestedAuditPayload(depth int) string {
	body := `"hello"`
	for range depth {
		body = `{"payload":` + body + `}`
	}
	return body
}
