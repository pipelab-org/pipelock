// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func undecodablePolicyConfig(action string, enforce bool, rule config.RequestPolicyRule) *config.Config {
	cfg := reqPolicyConfig(rule)
	cfg.RequestBodyScanning.Enabled = false
	cfg.RequestPolicy.OnParseError = config.ActionWarn
	cfg.RequestPolicy.OnOpaqueOperation = config.ActionWarn
	cfg.RequestPolicy.OnUndecodableEncoding = action
	cfg.Enforce = &enforce
	return cfg
}

func TestRequestPolicyUndecodableEncodingSurfaces(t *testing.T) {
	plain := []byte(`{"action":"deleteRecord"}`)
	attacks := []struct {
		name string
		body []byte
		enc  string
	}{
		{name: "stacked gzip", body: gzipRequestBody(t, gzipRequestBody(t, plain)), enc: "gzip, gzip"},
		{name: "unknown coding", body: gzipRequestBody(t, plain), enc: "br"},
		{name: "gzip that does not finish", body: append(gzipRequestBody(t, plain), gzipRequestBody(t, []byte("x"))...), enc: "gzip"},
	}
	actions := []struct {
		name        string
		action      string
		wantStatus  map[string]int
		wantHits    int32
		wantAudit   string
		wantReceipt bool
	}{
		{name: "default block", wantStatus: map[string]int{"forward": http.StatusForbidden, "reverse": http.StatusForbidden, "intercept": http.StatusForbidden}, wantAudit: rpRuleName, wantReceipt: true},
		{name: "explicit block", action: config.ActionBlock, wantStatus: map[string]int{"forward": http.StatusForbidden, "reverse": http.StatusForbidden, "intercept": http.StatusForbidden}, wantAudit: rpRuleName, wantReceipt: true},
		{name: "warn", action: config.ActionWarn, wantStatus: map[string]int{"forward": http.StatusNoContent, "reverse": http.StatusOK, "intercept": http.StatusOK}, wantHits: 1, wantAudit: "action=warn"},
		{name: "allow", action: config.ActionAllow, wantStatus: map[string]int{"forward": http.StatusNoContent, "reverse": http.StatusOK, "intercept": http.StatusOK}, wantHits: 1},
	}
	for _, action := range actions {
		for _, attack := range attacks {
			t.Run(action.name+"/"+attack.name, func(t *testing.T) {
				cfg := undecodablePolicyConfig(action.action, true, discriminatorBlockRule())
				observeUndecodableSurfaces(t, cfg, attack.body, attack.enc, action.wantStatus, action.wantHits, action.wantAudit, action.wantReceipt)
			})
		}
	}
}

func TestRequestPolicyUndecodableEncodingDecodableStillMatches(t *testing.T) {
	cfg := undecodablePolicyConfig("", true, discriminatorBlockRule())
	blocked := gzipRequestBody(t, []byte(`{"action":"deleteRecord"}`))
	benign := gzipRequestBody(t, []byte(`{"action":"list"}`))
	observeUndecodableSurfaces(t, cfg, blocked, "gzip", map[string]int{
		"forward": http.StatusForbidden, "reverse": http.StatusForbidden, "intercept": http.StatusForbidden,
	}, 0, rpRuleName, true)
	observeUndecodableSurfaces(t, cfg, benign, "gzip", map[string]int{
		"forward": http.StatusNoContent, "reverse": http.StatusOK, "intercept": http.StatusOK,
	}, 1, "", false)
}

func TestRequestPolicyUndecodableEncodingAuditMode(t *testing.T) {
	plain := gzipRequestBody(t, gzipRequestBody(t, []byte(`{"action":"deleteRecord"}`)))
	for _, action := range []string{"", config.ActionBlock} {
		name := "default"
		if action == config.ActionBlock {
			name = "explicit block"
		}
		t.Run(name, func(t *testing.T) {
			cfg := undecodablePolicyConfig(action, false, discriminatorBlockRule())
			status, auditText, rec := forwardUndecodable(t, cfg, plain, "gzip, gzip")
			if status != http.StatusForbidden {
				t.Fatalf("status=%d, want 403", status)
			}
			if !strings.Contains(auditText, rpRuleName) {
				t.Fatalf("audit = %s", auditText)
			}
			if rec.ActionRecord.Layer != blockLayerRequestPolicy || rec.ActionRecord.Pattern != rpRuleName {
				t.Fatalf("receipt = %+v", rec.ActionRecord)
			}
		})
	}
	cfg := undecodablePolicyConfig(config.ActionWarn, false, discriminatorBlockRule())
	status, auditText, rec := forwardUndecodable(t, cfg, plain, "gzip, gzip")
	if status != http.StatusNoContent || !strings.Contains(auditText, "action=warn") || rec.ActionRecord.Layer != "" {
		t.Fatalf("warn audit mode status=%d audit=%s receipt=%+v", status, auditText, rec.ActionRecord)
	}
}

func TestRequestPolicyUndecodableEncodingReload(t *testing.T) {
	body := gzipRequestBody(t, []byte(`{"action":"deleteRecord"}`))
	cfg := undecodablePolicyConfig("", true, discriminatorBlockRule())
	p := newTestProxyWithConfig(t, cfg)
	if !undecodablePreparedBlock(t, p, body) {
		t.Fatal("omitted action forwarded")
	}
	cfg.RequestPolicy.OnUndecodableEncoding = config.ActionAllow
	if err := p.setupRequestPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	p.cfgPtr.Store(cfg)
	if undecodablePreparedBlock(t, p, body) {
		t.Fatal("reload to allow still blocked")
	}
	if err := p.setupRequestPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	if undecodablePreparedBlock(t, p, body) {
		t.Fatal("reload without change blocked")
	}
	cfg.RequestPolicy.OnUndecodableEncoding = config.ActionWarn
	if err := p.setupRequestPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	p.cfgPtr.Store(cfg)
	if undecodablePreparedBlock(t, p, body) {
		t.Fatal("reload to warn blocked")
	}
}

func TestRequestPolicyUndecodableEncodingExceptStillBlocks(t *testing.T) {
	rule := config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts:        []string{rpTestHost},
			Methods:      []string{http.MethodPost},
			PathPrefixes: []string{"/v1/upload"},
		},
		Except: &config.RequestPolicyException{Field: "destinationId", Values: []string{"archive"}},
		Reason: "archive is the only allowed destination",
	}
	cfg := undecodablePolicyConfig(config.ActionAllow, true, rule)
	body := gzipRequestBody(t, []byte(`{"destinationId":"archive"}`))
	status, _, _ := forwardUndecodable(t, cfg, body, "br")
	if status != http.StatusForbidden {
		t.Fatalf("except status=%d, want 403", status)
	}
}

func TestRequestPolicyUndecodableEncodingSkipsRouteOnly(t *testing.T) {
	cfg := undecodablePolicyConfig("", true, blockRule(http.MethodDelete))
	body := gzipRequestBody(t, []byte(`{"action":"deleteRecord"}`))
	status, _, _ := forwardUndecodable(t, cfg, body, "br")
	if status != http.StatusNoContent {
		t.Fatalf("route-only status=%d, want 204", status)
	}
}

func TestRequestPolicyUndecodableAllowSkipsKeyIntegrity(t *testing.T) {
	cfg := undecodablePolicyConfig(config.ActionAllow, true, graphqlBlockRule())
	cfg.RequestPolicy.OnParseError = config.ActionBlock
	body := gzipRequestBody(t, []byte(deleteRecordGraphQLBody()))
	status, _, _ := forwardUndecodable(t, cfg, body, "br")
	if status != http.StatusNoContent {
		t.Fatalf("allow status=%d, want 204", status)
	}
}

func observeUndecodableSurfaces(t *testing.T, cfg *config.Config, body []byte, encoding string, wantStatus map[string]int, wantHits int32, wantAudit string, wantReceipt bool) {
	t.Helper()
	t.Run("forward", func(t *testing.T) {
		status, auditText, rec := forwardUndecodable(t, cfg, body, encoding)
		assertUndecodableOutcome(t, status, wantStatus["forward"], auditText, wantAudit, rec, wantReceipt, wantHits)
	})
	t.Run("reverse", func(t *testing.T) {
		status, hits, auditText, rec := reverseUndecodable(t, cfg, body, encoding)
		if hits != wantHits {
			t.Fatalf("hits=%d, want %d", hits, wantHits)
		}
		assertUndecodableOutcome(t, status, wantStatus["reverse"], auditText, wantAudit, rec, wantReceipt, wantHits)
	})
	t.Run("intercept", func(t *testing.T) {
		status, auditText, rec := interceptUndecodable(t, cfg, body, encoding)
		assertUndecodableOutcome(t, status, wantStatus["intercept"], auditText, wantAudit, rec, wantReceipt, wantHits)
	})
}

func assertUndecodableOutcome(t *testing.T, status, want int, auditText, wantAudit string, rec receipt.Receipt, wantReceipt bool, _ int32) {
	t.Helper()
	if status != want {
		t.Fatalf("status=%d, want %d", status, want)
	}
	if wantAudit != "" && !strings.Contains(auditText, wantAudit) {
		t.Fatalf("audit = %s", auditText)
	}
	if wantReceipt {
		if rec.ActionRecord.Layer != blockLayerRequestPolicy || rec.ActionRecord.Pattern != rpRuleName {
			t.Fatalf("receipt = %+v", rec.ActionRecord)
		}
		return
	}
	if rec.ActionRecord.Layer != "" {
		t.Fatalf("unexpected receipt %+v", rec.ActionRecord)
	}
}

func forwardUndecodable(t *testing.T, cfg *config.Config, body []byte, encoding string) (int, string, receipt.Receipt) {
	t.Helper()
	auditPath, logger := codedAuditLogger(t)
	rph := newReceiptProxyHelper(t)
	proxyAddr, p, cleanup := setupForwardProxyWithLogger(t, logger, func(got *config.Config) {
		cloned := cfg.Clone()
		*got = *cloned
	})
	t.Cleanup(cleanup)
	p.receiptEmitterPtr.Store(rph.emitter)
	up := &codedUpstream{}
	backend := httptest.NewServer(up.handler())
	t.Cleanup(backend.Close)
	installForwardTestDialer(p, backend.Listener.Addr().String())
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.example.com/v1/upload", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", encoding)
	resp, err := forwardHTTPClient(t, proxyAddr).Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	_, _ = io.ReadAll(resp.Body)
	auditText := codedAuditText(t, logger, auditPath)
	rec := receiptFromHelper(t, rph, resp.StatusCode)
	if resp.StatusCode == http.StatusNoContent && up.hits.Load() != 1 {
		t.Fatalf("forwarded hits=%d", up.hits.Load())
	}
	if resp.StatusCode == http.StatusForbidden && up.hits.Load() != 0 {
		t.Fatalf("blocked hits=%d", up.hits.Load())
	}
	if resp.Header.Get(blockreason.HeaderReason) == "" && resp.StatusCode == http.StatusForbidden {
		t.Fatal("block response missing reason")
	}
	return resp.StatusCode, auditText, rec
}

func reverseUndecodable(t *testing.T, cfg *config.Config, body []byte, encoding string) (int, int32, string, receipt.Receipt) {
	t.Helper()
	var hits int32
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read: %v", err)
		}
		gotBody = append([]byte(nil), buf...)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cloned := cfg.Clone()
	for i := range cloned.RequestPolicy.Rules {
		hosts := append([]string(nil), cloned.RequestPolicy.Rules[i].Route.Hosts...)
		for j, host := range hosts {
			if host == rpTestHost {
				hosts[j] = upstreamURL.Hostname()
			}
		}
		cloned.RequestPolicy.Rules[i].Route.Hosts = hosts
	}
	auditPath, logger := codedAuditLogger(t)
	sc := scanner.MustNew(cloned)
	t.Cleanup(sc.Close)
	p, err := New(cloned, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	t.Cleanup(p.Close)
	rph := newReceiptProxyHelper(t)
	p.receiptEmitterPtr.Store(rph.emitter)
	handler := NewReverseProxy(upstreamURL, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
	handler.SetRequestPolicyFn(p.ApplyRequestPolicy)
	handler.SetRequestPolicyPrepareFn(p.PrepareRequestPolicyBody)
	handler.SetReceiptEmitter(&p.receiptEmitterPtr)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/v1/upload", bytes.NewReader(body))
	req.Host = rpTestHost
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", encoding)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	auditText := codedAuditText(t, logger, auditPath)
	rec := receiptFromHelper(t, rph, w.Code)
	if w.Code == http.StatusOK && (hits != 1 || !bytes.Equal(gotBody, body)) {
		t.Fatalf("hits=%d body match=%v", hits, bytes.Equal(gotBody, body))
	}
	return w.Code, hits, auditText, rec
}

func interceptUndecodable(t *testing.T, cfg *config.Config, body []byte, encoding string) (int, string, receipt.Receipt) {
	t.Helper()
	auditPath, logger := codedAuditLogger(t)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	t.Cleanup(p.Close)
	rph := newReceiptProxyHelper(t)
	p.receiptEmitterPtr.Store(rph.emitter)
	ic := &InterceptContext{
		TargetHost: rpTestHost, TargetPort: "443", Config: cfg, Scanner: sc,
		Logger: logger, Metrics: p.metrics, Proxy: p, RequestID: "undecodable",
	}
	var hits int32
	handler := newInterceptHandler(ic, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hits++
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read: %v", err)
		}
		if !bytes.Equal(buf, body) {
			t.Errorf("upstream body mismatch")
		}
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusOK)
		return rec.Result(), nil
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+rpTestHost+"/v1/upload", bytes.NewReader(body))
	req.Host = rpTestHost + ":443"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", encoding)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	auditText := codedAuditText(t, logger, auditPath)
	rec := receiptFromHelper(t, rph, w.Code)
	if w.Code == http.StatusOK && hits != 1 {
		t.Fatalf("hits=%d", hits)
	}
	if w.Code == http.StatusForbidden && hits != 0 {
		t.Fatalf("blocked hits=%d", hits)
	}
	return w.Code, auditText, rec
}

func undecodablePreparedBlock(t *testing.T, p *Proxy, body []byte) bool {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/v1/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "br")
	in := requestPolicyInput{
		Host: rpTestHost, Method: http.MethodPost, Path: "/v1/upload",
		ContentType: "application/json", Headers: req.Header, AuditCtx: audit.LogContext{},
	}
	if res := p.prepareRequestPolicyBody(req, &in); res.Block {
		return true
	}
	return p.applyRequestPolicy(in).Block
}

func receiptFromHelper(t *testing.T, rph *receiptProxyHelper, status int) receipt.Receipt {
	t.Helper()
	if status == http.StatusForbidden {
		return rph.requireReceipt(t, blockLayerRequestPolicy)
	}
	found := rph.findReceipts(t)
	for _, rec := range found {
		if rec.ActionRecord.Layer == blockLayerRequestPolicy {
			return rec
		}
	}
	return receipt.Receipt{}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestRequestPolicyUndecodableEncodingNamesTheCause checks that a refusal made
// by on_undecodable_encoding says so, instead of repeating the reason of the
// rule whose body it could not read.
func TestRequestPolicyUndecodableEncodingNamesTheCause(t *testing.T) {
	plain := []byte(`{"action":"deleteRecord"}`)
	cfg := undecodablePolicyConfig("", true, discriminatorBlockRule())
	status, auditText, _ := forwardUndecodable(t, cfg, gzipRequestBody(t, plain), "br")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
	if !strings.Contains(auditText, rpRuleName+": "+requestPolicyUndecodableReason) {
		t.Fatalf("block record does not name the undecodable coding: %s", auditText)
	}
	warnCfg := undecodablePolicyConfig(config.ActionWarn, true, discriminatorBlockRule())
	status, auditText, _ = forwardUndecodable(t, warnCfg, gzipRequestBody(t, plain), "br")
	if status != http.StatusNoContent {
		t.Fatalf("warn status = %d, want 204", status)
	}
	if !strings.Contains(auditText, "cause="+requestPolicyUndecodableReason) {
		t.Fatalf("warn record does not name the undecodable coding: %s", auditText)
	}
}

func TestRequestPolicyUndecodableBatchOnly(t *testing.T) {
	for _, tc := range []struct {
		action string
		block  bool
	}{{"", true}, {config.ActionWarn, false}, {config.ActionAllow, false}} {
		t.Run(tc.action, func(t *testing.T) {
			cfg := batchReqPolicyConfig()
			cfg.RequestPolicy.Rules = nil
			cfg.RequestPolicy.OnUndecodableEncoding = tc.action
			cfg.RequestPolicy.OnParseError = config.ActionBlock
			p := newTestProxyWithConfig(t, cfg)
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/v1.0/$batch", strings.NewReader("not an envelope"))
			r.Header.Set("Content-Encoding", "br")
			in := requestPolicyInput{Host: rpTestHost, Method: http.MethodPost, Path: "/v1.0/$batch", Headers: r.Header}
			result := p.prepareRequestPolicyBody(r, &in)
			if !result.Block {
				result = p.applyRequestPolicy(in)
			}
			if result.Block != tc.block {
				t.Fatalf("block=%t, want %t", result.Block, tc.block)
			}
		})
	}
}

// TestRequestPolicyUndecodableEncodingRecordedOnce checks that one request
// produces one record: a default block is finalized where the body is
// prepared and is not finalized again, and a warn is recorded once.
func TestRequestPolicyUndecodableEncodingRecordedOnce(t *testing.T) {
	plain := []byte(`{"action":"deleteRecord"}`)
	body := gzipRequestBody(t, plain)

	status, auditText, rec := forwardUndecodable(t, undecodablePolicyConfig("", true, discriminatorBlockRule()), body, "br")
	if status != http.StatusForbidden {
		t.Fatalf("block status = %d, want 403", status)
	}
	if got := strings.Count(auditText, rpRuleName+": "+requestPolicyUndecodableReason); got != 1 {
		t.Fatalf("block recorded %d times, want 1: %s", got, auditText)
	}
	if rec.ActionRecord.Layer != blockLayerRequestPolicy || rec.ActionRecord.Pattern != rpRuleName {
		t.Fatalf("block receipt = %+v", rec.ActionRecord)
	}

	status, auditText, _ = forwardUndecodable(t, undecodablePolicyConfig(config.ActionWarn, true, discriminatorBlockRule()), body, "br")
	if status != http.StatusNoContent {
		t.Fatalf("warn status = %d, want 204", status)
	}
	if got := strings.Count(auditText, "cause="+requestPolicyUndecodableReason); got != 1 {
		t.Fatalf("warn recorded %d times, want 1: %s", got, auditText)
	}
}

// TestRequestPolicyUndecodableEncodingShadowRuleForwards checks shadow
// semantics: a shadow rule whose body cannot be decoded is logged with
// shadow=true and the request is forwarded, even under the default block.
func TestRequestPolicyUndecodableEncodingShadowRuleForwards(t *testing.T) {
	rule := discriminatorBlockRule()
	rule.Shadow = true
	body := gzipRequestBody(t, []byte(`{"action":"deleteRecord"}`))
	status, auditText, _ := forwardUndecodable(t, undecodablePolicyConfig("", true, rule), body, "br")
	if status != http.StatusNoContent {
		t.Fatalf("shadow status = %d, want 204", status)
	}
	if !strings.Contains(auditText, "shadow=true cause="+requestPolicyUndecodableReason) {
		t.Fatalf("shadow record missing: %s", auditText)
	}
}

// TestRequestPolicyUndecodableEncodingEmptyBody checks a request that declares
// a coding and sends no body. There are no bytes for a body rule to miss, so
// the request is not refused for its coding.
func TestRequestPolicyUndecodableEncodingEmptyBody(t *testing.T) {
	for _, enc := range []string{"gzip", "br"} {
		t.Run(enc, func(t *testing.T) {
			status, auditText, _ := forwardUndecodable(t, undecodablePolicyConfig("", true, discriminatorBlockRule()), []byte{}, enc)
			if status != http.StatusNoContent {
				t.Fatalf("empty body status = %d, want 204", status)
			}
			if strings.Contains(auditText, requestPolicyUndecodableReason) {
				t.Fatalf("empty body was recorded as undecodable: %s", auditText)
			}
		})
	}
}
