// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestURLDecisionTransports(t *testing.T) {
	t.Parallel()
	for _, transport := range []string{TransportFetch, TransportForward, TransportConnect, TransportWS} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.WebSocketProxy.Enabled = true
			cfg.FetchProxy.Monitoring.Blocklist = []string{inventoryHost}
			h := &inventoryHarness{scanners: make(map[string]*scanner.Scanner)}
			p, _, rt := h.proxy(t, cfg, "ok", "text/plain")
			target := inventoryTarget
			method := http.MethodGet
			switch transport {
			case TransportFetch:
				target = "/fetch?url=" + url.QueryEscape(inventoryTarget)
			case TransportConnect:
				method = http.MethodConnect
				target = inventoryHost + ":443"
			case TransportWS:
				target = "/ws?url=" + url.QueryEscape("wss://"+inventoryHost+"/submit")
			}
			req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
			req.RemoteAddr = "192.0.2.10:12345"
			w := httptest.NewRecorder()
			switch transport {
			case TransportFetch:
				p.handleFetch(w, req)
			case TransportForward:
				p.handleForwardHTTP(w, req)
			case TransportConnect:
				p.handleConnect(w, req)
			case TransportWS:
				p.handleWebSocket(w, req)
			}
			if w.Code != http.StatusForbidden || rt.called {
				t.Fatalf("status=%d upstream called=%v: %s", w.Code, rt.called, w.Body.String())
			}
			assertMetricSampleValue(t, p.metrics, `pipelock_url_check_decisions_total{check="blocklist",outcome="blocked",part="url",transport="`+transport+`"}`, 1)
			assertMetricSampleValue(t, p.metrics, `pipelock_url_check_decisions_total{check="entropy",outcome="not_evaluated",part="url",transport="`+transport+`"}`, 1)
		})
	}
}

func TestURLDecisionReverseSubmit(t *testing.T) {
	t.Parallel()
	cfg, upstream := submitProfileTestConfig("https://" + inventoryHost)
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.Blocklist = []string{inventoryHost}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	m := metrics.New()
	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)
	rp := NewReverseProxy(upstream, &cfgPtr, &scPtr, audit.NewNop(), m, killswitch.New(cfg), nil, nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/batch", strings.NewReader(`{"clean":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d: %s", w.Code, w.Body.String())
	}
	assertMetricSampleValue(t, m, `pipelock_url_check_decisions_total{check="blocklist",outcome="blocked",part="url",transport="reverse"}`, 1)
	assertMetricSampleValue(t, m, `pipelock_url_check_decisions_total{check="entropy",outcome="not_evaluated",part="url",transport="reverse"}`, 1)
}

func TestURLDecisionRedirects(t *testing.T) {
	t.Parallel()
	for _, transport := range []string{TransportFetch, TransportForward} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, inventoryTarget, http.StatusFound)
			}))
			t.Cleanup(upstream.Close)
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
			cfg.FetchProxy.Monitoring.Blocklist = []string{inventoryHost}
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			target := upstream.URL + "/redirect"
			if transport == TransportFetch {
				target = "/fetch?url=" + url.QueryEscape(target)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			w := httptest.NewRecorder()
			if transport == TransportFetch {
				p.handleFetch(w, req)
			} else {
				p.handleForwardHTTP(w, req)
			}
			if w.Code != http.StatusForbidden {
				t.Fatalf("status=%d: %s", w.Code, w.Body.String())
			}
			assertMetricSampleValue(t, p.metrics, `pipelock_url_check_decisions_total{check="blocklist",outcome="allowed",part="url",transport="`+transport+`"}`, 1)
			assertMetricSampleValue(t, p.metrics, `pipelock_url_check_decisions_total{check="blocklist",outcome="blocked",part="url",transport="`+transport+`"}`, 1)
		})
	}
}
