// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestAuditModeInterceptRefusals records TLS-intercept handling with enforce
// false. A core credential and a compressed body stay refused with status 403.
// Those refusals log blocked and intercept_http, increment
// pipelock_tls_request_blocked_total, and write no block receipt. An operator
// pattern and a blocklisted host are delivered, and their audit events are
// anomaly and intercept_http. The kill switch answers 503, logs blocked and
// intercept_http, increments the denial counter, and writes no block receipt.
func TestAuditModeInterceptRefusals(t *testing.T) {
	core := auditFloorValue("core")
	policy := auditFloorValue("dlp")
	cases := []struct {
		name, body, encoding string
		blocklist, pattern   bool
		kill                 bool
		want                 auditModeObservation
	}{
		{
			name: "core credential", body: "token=" + core,
			want: auditModeObservation{status: http.StatusForbidden, events: "blocked,intercept_http", blockMetrics: "pipelock_tls_request_blocked_total"},
		},
		{
			name: "operator pattern", body: "token=" + policy, pattern: true,
			want: auditModeObservation{status: http.StatusOK, delivered: true, upstream: 1, events: "anomaly,intercept_http"},
		},
		{
			name: "blocklisted host", blocklist: true,
			want: auditModeObservation{status: http.StatusOK, delivered: true, upstream: 1, events: "anomaly,intercept_http"},
		},
		{
			name: "compressed body", body: "not-gzip", encoding: "gzip",
			want: auditModeObservation{status: http.StatusForbidden, events: "blocked,intercept_http", blockMetrics: "pipelock_tls_request_blocked_total"},
		},
		{
			name: "kill switch", kill: true,
			want: auditModeObservation{status: http.StatusServiceUnavailable, events: "blocked,intercept_http", blockMetrics: "pipelock_kill_switch_denials_total"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			rig := newAuditModeRig(t, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
				cfg.KillSwitch.Enabled = tc.kill
				if tc.blocklist {
					cfg.FetchProxy.Monitoring.Blocklist = []string{"peer.example"}
				}
				if tc.pattern {
					auditOperatorPattern(cfg)
				}
			})
			cfg := rig.proxy.cfgPtr.Load()
			handler := newInterceptHandler(&InterceptContext{
				TargetHost: "peer.example", TargetPort: "443", Config: cfg,
				Scanner: rig.proxy.scannerPtr.Load(), Logger: rig.proxy.logger, Metrics: rig.proxy.metrics,
				ClientIP: testLoopbackIP, RequestID: "audit-mode-intercept", Agent: agentAnonymous,
				KillSwitch: rig.proxy.ks,
			}, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				hits.Add(1)
				return &http.Response{
					StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}},
					Body: http.NoBody, Request: r,
				}, nil
			}))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://peer.example/x", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "text/plain")
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			delivered := w.Code == http.StatusOK && hits.Load() == 1
			assertAuditMode(t, rig.observation(t, w.Code, delivered, hits.Load()), tc.want)
		})
	}
}
