// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
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

// TestRequestPolicyAuditModeTransports is the premise for configured
// request-policy blocks. With enforce false, a rule block on an inspected
// request is forwarded and the upstream receives it. With enforce true, the
// same request is refused with 403.
func TestRequestPolicyAuditModeTransports(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		enforce bool
		run     func(t *testing.T, enforce bool) policyAuditObs
	}{
		{"fetch", false, runFetchPolicyAudit},
		{"fetch", true, runFetchPolicyAudit},
		{"redirect", false, runRedirectPolicyAudit},
		{"redirect", true, runRedirectPolicyAudit},
		{"forward", false, runForwardPolicyAudit},
		{"forward", true, runForwardPolicyAudit},
		{"connect", false, runConnectPolicyAudit},
		{"connect", true, runConnectPolicyAudit},
		{"intercept", false, runInterceptPolicyAudit},
		{"intercept", true, runInterceptPolicyAudit},
		{"reverse", false, runReversePolicyAudit},
		{"reverse", true, runReversePolicyAudit},
		{"websocket", false, runWebSocketPolicyAudit},
		{"websocket", true, runWebSocketPolicyAudit},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/enforce=%t", tc.name, tc.enforce), func(t *testing.T) {
			t.Parallel()
			assertPolicyAudit(t, tc.enforce, tc.run(t, tc.enforce))
		})
	}
}

type policyAuditObs struct {
	status   int
	upstream int32
	reason   string
	logs     string
	metrics  *metrics.Metrics
	receipts *receiptProxyHelper
}

func assertPolicyAudit(t *testing.T, enforce bool, got policyAuditObs) {
	t.Helper()
	if enforce {
		if got.status != http.StatusForbidden {
			t.Fatalf("status=%d logs=%s", got.status, got.logs)
		}
		if got.upstream != 0 {
			t.Fatalf("upstream=%d, want 0", got.upstream)
		}
		if got.reason != "request_policy_deny" {
			t.Fatalf("reason=%q", got.reason)
		}
		if !strings.Contains(got.logs, `"event":"blocked"`) {
			t.Fatalf("logs=%s", got.logs)
		}
		if !strings.Contains(got.logs, `"block_class":"protective"`) {
			t.Fatalf("enforced block missing class: %s", got.logs)
		}
		if action := requestPolicyActionLabel(t, got.metrics); action != config.ActionBlock {
			t.Fatalf("metric action=%q", action)
		}
		if got.receipts != nil && !auditBlockReceipt(t, got.receipts) {
			t.Fatal("missing block receipt")
		}
		return
	}
	if got.status != http.StatusOK && got.status != http.StatusSwitchingProtocols {
		t.Fatalf("status=%d reason=%q logs=%s", got.status, got.reason, got.logs)
	}
	if got.upstream != 1 {
		t.Fatalf("upstream=%d, want 1", got.upstream)
	}
	if got.reason != "" {
		t.Fatalf("block reason=%q", got.reason)
	}
	if strings.Contains(got.logs, `"event":"blocked"`) {
		t.Fatalf("observed block wrote blocked: %s", got.logs)
	}
	if !strings.Contains(got.logs, "would_block=true") || !strings.Contains(got.logs, `"event":"anomaly"`) {
		t.Fatalf("logs=%s", got.logs)
	}
	if action := requestPolicyActionLabel(t, got.metrics); action != "audit_block" {
		t.Fatalf("metric action=%q", action)
	}
	if got.receipts != nil && auditBlockReceipt(t, got.receipts) {
		t.Fatal("observed block wrote a block receipt")
	}
}

func requestPolicyActionLabel(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	if m == nil {
		t.Fatal("metrics nil")
	}
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, family := range families {
		if family.GetName() != "pipelock_request_policy_decisions_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricValue(metric) <= 0 {
				continue
			}
			rule, action := "", ""
			for _, label := range metric.GetLabel() {
				switch label.GetName() {
				case "rule":
					rule = label.GetValue()
				case "action":
					action = label.GetValue()
				}
			}
			if rule == rpRuleName {
				actions = append(actions, action)
			}
		}
	}
	if len(actions) != 1 {
		t.Fatalf("decision actions=%v", actions)
	}
	return actions[0]
}

func policyAuditConfig(enforce bool, rules ...config.RequestPolicyRule) *config.Config {
	cfg := reqPolicyConfig(rules...)
	flag := enforce
	cfg.Enforce = &flag
	return cfg
}

func policyAuditRig(t *testing.T, cfg *config.Config) (*Proxy, *bytes.Buffer, *receiptProxyHelper) {
	t.Helper()
	var logs bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m, WithKillSwitch(killswitch.New(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	receipts := newReceiptProxyHelperWithMetrics(t, m)
	p.receiptEmitterPtr.Store(receipts.emitter)
	return p, &logs, receipts
}

func runFetchPolicyAudit(t *testing.T, enforce bool) policyAuditObs {
	t.Helper()
	var hits atomic.Int32
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret" {
			hits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	host := upstreamURLHost(t, upstream.URL)
	cfg := policyAuditConfig(enforce, config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodGet}},
		Reason: "dangerous operation requires operator approval",
	})
	p, logs, receipts := policyAuditRig(t, cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL+"/v1/secret"), nil)
	p.buildHandler(p.buildMux()).ServeHTTP(w, req)
	return policyAuditObs{status: w.Code, upstream: hits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics, receipts: receipts}
}

func runRedirectPolicyAudit(t *testing.T, enforce bool) policyAuditObs {
	t.Helper()
	var hits atomic.Int32
	final := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(final.Close)
	origin := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/v1/secret", http.StatusFound)
	}))
	t.Cleanup(origin.Close)
	host := upstreamURLHost(t, final.URL)
	cfg := policyAuditConfig(enforce, config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodGet}},
		Reason: "dangerous operation requires operator approval",
	})
	p, logs, receipts := policyAuditRig(t, cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(origin.URL), nil)
	p.buildHandler(p.buildMux()).ServeHTTP(w, req)
	return policyAuditObs{status: w.Code, upstream: hits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics, receipts: receipts}
}

func runForwardPolicyAudit(t *testing.T, enforce bool) policyAuditObs {
	t.Helper()
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/v1/jobs/1" {
			hits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	cfg := policyAuditConfig(enforce, blockRule(http.MethodDelete))
	p, logs, receipts := policyAuditRig(t, cfg)
	installForwardTestDialer(p, backend.Listener.Addr().String())
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "http://"+rpTestHost+"/v1/jobs/1", nil)
	p.buildHandler(http.NewServeMux()).ServeHTTP(w, req)
	return policyAuditObs{status: w.Code, upstream: hits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics, receipts: receipts}
}

func runConnectPolicyAudit(t *testing.T, enforce bool) policyAuditObs {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var hits atomic.Int32
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			hits.Add(1)
			_ = conn.Close()
		}
	}()
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg := policyAuditConfig(enforce, config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodConnect}},
		Reason: "host blocked for agent runtime",
	})
	p, logs, receipts := policyAuditRig(t, cfg)
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		p.buildHandler(http.NewServeMux()).ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	conn := dialProxy(t, strings.TrimPrefix(server.URL, "http://"))
	t.Cleanup(func() { _ = conn.Close() })
	target := ln.Addr().String()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	_ = conn.Close()
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("CONNECT handler did not return")
	}
	// The dial completes in the kernel before the accept loop counts it, so a
	// tunnel that opened waits for the count.
	if resp.StatusCode == http.StatusOK {
		deadline := time.Now().Add(5 * time.Second)
		for hits.Load() == 0 && time.Now().Before(deadline) {
			runtime.Gosched()
		}
	}
	return policyAuditObs{status: resp.StatusCode, upstream: hits.Load(), reason: resp.Header.Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics, receipts: receipts}
}

func runInterceptPolicyAudit(t *testing.T, enforce bool) policyAuditObs {
	t.Helper()
	cfg := policyAuditConfig(enforce, blockRule(http.MethodPost))
	p, logs, receipts := policyAuditRig(t, cfg)
	sc := p.scannerPtr.Load()
	var hits atomic.Int32
	ic := &InterceptContext{
		TargetHost: rpTestHost, TargetPort: "443", Config: cfg, Scanner: sc,
		Logger: p.logger, Metrics: p.metrics, Proxy: p, RequestID: "audit-rp",
		ClientIP: "192.0.2.1",
	}
	handler := newInterceptHandler(ic, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/jobs/1" {
			hits.Add(1)
		}
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusOK)
		return rec.Result(), nil
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+rpTestHost+"/v1/jobs/1", nil)
	req.Host = rpTestHost + ":443"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return policyAuditObs{status: w.Code, upstream: hits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics, receipts: receipts}
}

func runReversePolicyAudit(t *testing.T, enforce bool) policyAuditObs {
	t.Helper()
	var hits atomic.Int32
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			hits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := policyAuditConfig(enforce, config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{upstreamURL.Hostname()}, Methods: []string{http.MethodDelete}},
		Reason: "dangerous operation requires operator approval",
	})
	p, logs, receipts := policyAuditRig(t, cfg)
	handler := NewReverseProxy(upstreamURL, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
	handler.SetRequestPolicyFn(p.ApplyRequestPolicy)
	handler.SetRequestPolicyPrepareFn(p.PrepareRequestPolicyBody)
	handler.SetReceiptEmitter(&p.receiptEmitterPtr)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "http://"+rpTestHost+"/v1/jobs/1", nil)
	req.Host = rpTestHost
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return policyAuditObs{status: w.Code, upstream: hits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics, receipts: receipts}
}

func runWebSocketPolicyAudit(t *testing.T, enforce bool) policyAuditObs {
	t.Helper()
	backend, _, _, handshake := wsRecordingServerWithHandshake(t)
	host, _, err := net.SplitHostPort(backend)
	if err != nil {
		t.Fatal(err)
	}
	cfg := policyAuditConfig(enforce, config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodGet}},
		Reason: "dangerous operation requires operator approval",
	})
	cfg.WebSocketProxy.Enabled = true
	var logs auditLogBuffer
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	addr, proxy, cleanup := setupWSProxyWithLogger(t, logger, func(c *config.Config) {
		flag := enforce
		c.Enforce = &flag
		c.RequestPolicy.Enabled = true
		c.RequestPolicy.Rules = cfg.RequestPolicy.Rules
	}, nil, nil)
	t.Cleanup(cleanup)
	receipts := newReceiptProxyHelperWithMetrics(t, proxy.metrics)
	proxy.receiptEmitterPtr.Store(receipts.emitter)
	resp := requestWSHandshake(t, addr, backend, nil)
	defer func() { _ = resp.Body.Close() }()
	// The proxy writes the client 101 before it dials upstream, so the
	// backend handshake can land after this response is readable.
	if !enforce && resp.StatusCode == http.StatusSwitchingProtocols {
		deadline := time.Now().Add(5 * time.Second)
		for handshake() == nil && time.Now().Before(deadline) {
			runtime.Gosched()
		}
	}
	var hits int32
	if handshake() != nil {
		hits = 1
	}
	status := resp.StatusCode
	if status == http.StatusSwitchingProtocols && !enforce {
		status = http.StatusSwitchingProtocols
	}
	return policyAuditObs{status: status, upstream: hits, reason: resp.Header.Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: proxy.metrics, receipts: receipts}
}

func upstreamURLHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}
