// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestAuditModeFetchRefusals records the fetch handler with enforce false.
// A core credential, a metadata literal, and a private literal stay refused.
// A blocklisted host and an operator pattern are delivered, with an anomaly
// followed by an allowed event. The kill switch returns 503 and writes
// kill_switch_deny. That front-door denial does not write a block receipt.
func TestAuditModeFetchRefusals(t *testing.T) {
	upstreamBody := "ordinary-fetch-body"
	var hits atomic.Int32
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, upstreamBody)
	}))
	t.Cleanup(upstream.Close)

	core := auditFloorValue("core")
	policy := auditFloorValue("dlp")
	cases := []struct {
		name      string
		target    string
		kill      bool
		blocklist bool
		pattern   bool
		delivered bool
		want      auditModeObservation
	}{
		{
			name: "core credential", target: upstream.URL + "/x?token=" + core,
			want: auditModeObservation{status: http.StatusForbidden, events: "blocked", blockMetrics: "pipelock_requests_total", blockReceipt: true},
		},
		{
			name: "blocklisted host", target: upstream.URL + "/x", blocklist: true, delivered: true,
			want: auditModeObservation{status: http.StatusOK, delivered: true, upstream: 1, events: "anomaly,allowed"},
		},
		{
			name: "operator pattern", target: upstream.URL + "/x?token=" + policy, pattern: true, delivered: true,
			want: auditModeObservation{status: http.StatusOK, delivered: true, upstream: 1, events: "anomaly,allowed"},
		},
		{
			name: "metadata literal", target: "http://169.254.169.254/latest/meta-data/",
			want: auditModeObservation{status: http.StatusForbidden, events: "anomaly,blocked", blockMetrics: "pipelock_requests_total", blockReceipt: true},
		},
		{
			name: "private literal", target: "http://10.0.0.8/v1",
			want: auditModeObservation{status: http.StatusForbidden, events: "anomaly,blocked", blockMetrics: "pipelock_requests_total", blockReceipt: true},
		},
		{
			name: "kill switch", target: upstream.URL + "/x", kill: true,
			want: auditModeObservation{status: http.StatusServiceUnavailable, events: "kill_switch_deny", blockMetrics: "pipelock_kill_switch_denials_total"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			rig := newAuditModeRig(t, func(cfg *config.Config) {
				cfg.KillSwitch.Enabled = tc.kill
				if tc.blocklist {
					cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
				}
				if tc.pattern {
					auditOperatorPattern(cfg)
				}
			})
			mux := http.NewServeMux()
			mux.HandleFunc("/fetch", rig.proxy.handleFetch)
			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(tc.target), nil)
			rig.proxy.buildHandler(mux).ServeHTTP(w, req)
			var body FetchResponse
			if w.Body.Len() > 0 {
				_ = json.Unmarshal(w.Body.Bytes(), &body)
			}
			delivered := w.Code == http.StatusOK && !body.Blocked && body.Content == upstreamBody
			if delivered != tc.delivered {
				t.Fatalf("delivered=%v body=%s", delivered, w.Body.String())
			}
			assertAuditMode(t, rig.observation(t, w.Code, delivered, hits.Load()), tc.want)
		})
	}
}
