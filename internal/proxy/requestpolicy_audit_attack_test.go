// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

// Attack exchanges for audit-mode request policy. Each case runs once with
// enforce true and once with enforce false. A marked block on inspected
// content is observed in audit. An unmarked block is refused in both modes.

const (
	attackDiscRule = "disc-block"
	attackGQLRule  = "gql-block"
)

type attackExpect int

const (
	attackRefuse attackExpect = iota
	attackObserve
	attackRelease
)

type attackExchange struct {
	method        string
	path          string
	body          []byte
	encoding      string
	overrideName  string
	overrideValue string
	chunked       bool
	maxBody       int
	// contentLength, when contentLengthSet, replaces the length NewRequest
	// inferred. Zero keeps an earlier cross-request read from draining the
	// body before request policy.
	contentLength    int64
	contentLengthSet bool
	parse            string
	opaque           string
	undecodable      string
	rules            func(host string) []config.RequestPolicyRule
	batches          func(host string) []config.RequestPolicyBatch
	// bodyFrom, when set, builds the request body after the proxy exists so a
	// read can reload that proxy before the decision.
	bodyFrom func(p *Proxy) io.Reader
}

func attackConfig(enforce bool, parse, opaque, undecodable string, rules ...config.RequestPolicyRule) *config.Config {
	cfg := policyAuditConfig(enforce, rules...)
	cfg.RequestBodyScanning.Enabled = false
	if parse != "" {
		cfg.RequestPolicy.OnParseError = parse
	}
	if opaque != "" {
		cfg.RequestPolicy.OnOpaqueOperation = opaque
	}
	if undecodable != "" {
		cfg.RequestPolicy.OnUndecodableEncoding = undecodable
	}
	return cfg
}

func attackRoute(host, method, path, action string) config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name: rpRuleName, Action: action,
		Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{method}, PathPrefixes: []string{path}},
		Reason: "dangerous operation requires operator approval",
	}
}

func attackDisc(host, method, path string) config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name: attackDiscRule, Action: config.ActionBlock,
		Route:         config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{method}, PathPrefixes: []string{path}},
		Discriminator: &config.RequestPolicyDiscriminator{Field: "action", ValuePatterns: []string{`^delete`}},
		Reason:        "destructive operation",
	}
}

func attackGraphQL(host, method, path string) config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name: attackGQLRule, Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{method}, PathPrefixes: []string{path}},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes:    []string{"mutation"},
			RootFieldPatterns: []string{`^deleteRecord$`},
		},
		Reason: "dangerous operation requires operator approval",
	}
}

func attackBatch(host string) config.RequestPolicyBatch {
	return config.RequestPolicyBatch{
		Route:          config.RequestPolicyRoute{Hosts: []string{host}, PathPatterns: []string{`/\$batch$`}},
		RequestsField:  "requests",
		MethodField:    "method",
		URLField:       "url",
		BodyField:      "body",
		MaxSubRequests: 64,
	}
}

func attackExact(host, method, path string, body []byte) config.RequestPolicyRule {
	sum := sha256.Sum256(body)
	return config.RequestPolicyRule{
		Name: rpRuleName, Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{method}, PathPrefixes: []string{path}},
		Except: &config.RequestPolicyException{Requests: []config.RequestPolicyExactRequest{{
			URL:        "https://" + host + path,
			Method:     method,
			BodySHA256: hex.EncodeToString(sum[:]),
			ExpiresAt:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			Owner:      "operator",
			Reason:     "approved access",
		}}},
		Reason: "dangerous operation requires operator approval",
	}
}

func runAttackExchange(t *testing.T, transport string, enforce bool, ex attackExchange) (policyAuditObs, []byte) {
	t.Helper()
	var hits atomic.Int32
	gotBody := make(chan []byte, 1)
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, err := io.ReadAll(r.Body)
		if err == nil {
			select {
			case gotBody <- b:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	host := rpTestHost
	if transport == "reverse" {
		host = upstreamURLHost(t, upstream.URL)
	}
	cfg := attackConfig(enforce, ex.parse, ex.opaque, ex.undecodable, ex.rules(host)...)
	if ex.batches != nil {
		cfg.RequestPolicy.Batch = ex.batches(host)
	}
	if ex.maxBody > 0 {
		cfg.RequestBodyScanning.MaxBodyBytes = ex.maxBody
	}
	var obs policyAuditObs
	serve := func(p *Proxy, logs *bytes.Buffer, receipts *receiptProxyHelper, handler http.Handler) {
		t.Helper()
		payload := io.Reader(bytes.NewReader(ex.body))
		if ex.bodyFrom != nil {
			payload = ex.bodyFrom(p)
		}
		req := httptest.NewRequestWithContext(t.Context(), ex.method, "http://"+rpTestHost+ex.path, payload)
		req.Header.Set(headerContentType, contentTypeJSON)
		if ex.encoding != "" {
			req.Header.Set("Content-Encoding", ex.encoding)
		}
		if ex.overrideName != "" {
			req.Header.Set(ex.overrideName, ex.overrideValue)
		}
		if ex.chunked {
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}
			req.Header.Set("Trailer", "X-Vendor-Trace")
			req.Trailer = http.Header{"X-Vendor-Trace": []string{"hop"}}
		}
		if ex.contentLengthSet {
			req.ContentLength = ex.contentLength
		}
		if transport == "reverse" {
			req.Host = rpTestHost
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		obs = policyAuditObs{status: w.Code, upstream: hits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics, receipts: receipts}
	}
	switch transport {
	case "forward":
		p, logs, receipts := policyAuditRig(t, cfg)
		installForwardTestDialer(p, upstream.Listener.Addr().String())
		serve(p, logs, receipts, p.buildHandler(http.NewServeMux()))
	case "reverse":
		p, logs, receipts := policyAuditRig(t, cfg)
		parsed, err := url.Parse(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		handler := NewReverseProxy(parsed, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
		handler.SetRequestPolicyFn(p.ApplyRequestPolicy)
		handler.SetRequestPolicyPrepareFn(p.PrepareRequestPolicyBody)
		handler.SetReceiptEmitter(&p.receiptEmitterPtr)
		serve(p, logs, receipts, handler)
	default:
		t.Fatalf("transport %s", transport)
	}
	var seen []byte
	select {
	case seen = <-gotBody:
	default:
	}
	return obs, seen
}

func attackActions(t *testing.T, m *metrics.Metrics) map[string]string {
	t.Helper()
	out := map[string]string{}
	if m == nil {
		t.Fatal("metrics nil")
	}
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
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
			out[rule] = action
		}
	}
	return out
}

func attackEvents(logs string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(logs, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev map[string]any
		if json.Unmarshal([]byte(line), &ev) == nil {
			out = append(out, ev)
		}
	}
	return out
}

func attackBlockedFields(logs string) (class, reason string, found bool) {
	for _, ev := range attackEvents(logs) {
		if ev["event"] != "blocked" || ev["scanner"] != blockLayerRequestPolicy {
			continue
		}
		class, _ = ev["block_class"].(string)
		reason, _ = ev["reason"].(string)
		return class, reason, true
	}
	return "", "", false
}

func attackPolicyReceipt(t *testing.T, receipts *receiptProxyHelper) (pattern string, ok bool) {
	t.Helper()
	if receipts == nil {
		return "", false
	}
	for _, got := range receipts.findReceipts(t) {
		rec := got.ActionRecord
		if rec.Layer == blockLayerRequestPolicy && rec.Verdict == config.ActionBlock {
			return rec.Pattern, true
		}
	}
	return "", false
}

func assertAttackPair(t *testing.T, expect attackExpect, on, off policyAuditObs) {
	t.Helper()
	switch expect {
	case attackObserve:
		if on.status != http.StatusForbidden || on.upstream != 0 || on.reason != "request_policy_deny" {
			t.Fatalf("enforce status=%d upstream=%d reason=%q logs=%s", on.status, on.upstream, on.reason, on.logs)
		}
		if _, _, ok := attackBlockedFields(on.logs); !ok || !strings.Contains(on.logs, `"block_class":"protective"`) {
			t.Fatalf("enforce logs=%s", on.logs)
		}
		if off.status != http.StatusOK || off.upstream != 1 || off.reason != "" {
			t.Fatalf("audit status=%d upstream=%d reason=%q logs=%s", off.status, off.upstream, off.reason, off.logs)
		}
		if strings.Contains(off.logs, `"event":"blocked"`) || !strings.Contains(off.logs, `"event":"anomaly"`) || !strings.Contains(off.logs, "would_block=true") {
			t.Fatalf("audit logs=%s", off.logs)
		}
		onActions, offActions := attackActions(t, on.metrics), attackActions(t, off.metrics)
		if len(onActions) == 0 || len(offActions) == 0 {
			t.Fatalf("actions enforce=%v audit=%v", onActions, offActions)
		}
		for rule, action := range onActions {
			if action != config.ActionBlock {
				t.Fatalf("enforce action %s=%s", rule, action)
			}
			if offActions[rule] != "audit_block" {
				t.Fatalf("audit action %s=%q actions=%v", rule, offActions[rule], offActions)
			}
		}
		if pattern, ok := attackPolicyReceipt(t, on.receipts); !ok || pattern == "" {
			t.Fatal("enforce missing request_policy block receipt")
		}
		if _, ok := attackPolicyReceipt(t, off.receipts); ok {
			t.Fatal("audit wrote a request_policy block receipt")
		}
	case attackRefuse:
		if on.status != http.StatusForbidden || off.status != http.StatusForbidden {
			t.Fatalf("status enforce=%d audit=%d logs=%s | %s", on.status, off.status, on.logs, off.logs)
		}
		if on.upstream != 0 || off.upstream != 0 {
			t.Fatalf("upstream enforce=%d audit=%d", on.upstream, off.upstream)
		}
		if on.reason != "request_policy_deny" || off.reason != on.reason {
			t.Fatalf("reason enforce=%q audit=%q", on.reason, off.reason)
		}
		onClass, onWhy, onFound := attackBlockedFields(on.logs)
		offClass, offWhy, offFound := attackBlockedFields(off.logs)
		if !onFound || !offFound || onClass != "protective" || offClass != onClass || offWhy != onWhy {
			t.Fatalf("blocked enforce=%q/%q audit=%q/%q logs=%s | %s", onClass, onWhy, offClass, offWhy, on.logs, off.logs)
		}
		onActions, offActions := attackActions(t, on.metrics), attackActions(t, off.metrics)
		if len(onActions) == 0 || len(onActions) != len(offActions) {
			t.Fatalf("actions enforce=%v audit=%v", onActions, offActions)
		}
		for rule, action := range onActions {
			if action != config.ActionBlock || offActions[rule] != config.ActionBlock {
				t.Fatalf("actions enforce=%v audit=%v", onActions, offActions)
			}
		}
		onPattern, onOK := attackPolicyReceipt(t, on.receipts)
		offPattern, offOK := attackPolicyReceipt(t, off.receipts)
		if !onOK || !offOK || onPattern != offPattern {
			t.Fatalf("receipt enforce=%q/%v audit=%q/%v", onPattern, onOK, offPattern, offOK)
		}
	case attackRelease:
		if on.status != http.StatusOK || off.status != http.StatusOK || on.upstream != 1 || off.upstream != 1 {
			t.Fatalf("status/upstream enforce=%d/%d audit=%d/%d logs=%s | %s", on.status, on.upstream, off.status, off.upstream, on.logs, off.logs)
		}
		if strings.Contains(on.logs, `"event":"blocked"`) || strings.Contains(off.logs, `"event":"blocked"`) || strings.Contains(on.logs, "would_block=true") || strings.Contains(off.logs, "would_block=true") {
			t.Fatalf("finding leaked logs=%s | %s", on.logs, off.logs)
		}
		if _, ok := attackPolicyReceipt(t, on.receipts); ok {
			t.Fatal("release wrote a request_policy block receipt")
		}
		if _, ok := attackPolicyReceipt(t, off.receipts); ok {
			t.Fatal("release wrote a request_policy block receipt")
		}
	default:
		t.Fatalf("expect %d", expect)
	}
}

func runAttackPair(t *testing.T, transport string, expect attackExpect, ex attackExchange) (onBody, offBody []byte) {
	t.Helper()
	on, onBody := runAttackExchange(t, transport, true, ex)
	off, offBody := runAttackExchange(t, transport, false, ex)
	assertAttackPair(t, expect, on, off)
	return onBody, offBody
}

func TestRequestPolicyAuditAttackDiscriminator(t *testing.T) {
	t.Parallel()
	bodies := []struct {
		name string
		body string
		knob string
	}{
		{name: "A1_invalid_json", body: "not-json", knob: "parse"},
		{name: "A2_non_object", body: "[1]", knob: "opaque"},
		{name: "A3_duplicate_key", body: `{"action":"list","action":"deleteAll"}`, knob: "opaque"},
		{name: "A4_key_alias", body: `{"Action":"deleteAll"}`, knob: "opaque"},
		{name: "A4_key_alias_both", body: `{"action":"list","Action":"deleteAll"}`, knob: "opaque"},
		{name: "A4_key_alias_folded", body: `{"ACTION":"deleteAll"}`, knob: "opaque"},
		{name: "A5_non_string", body: `{"action":1}`, knob: "opaque"},
	}
	for _, body := range bodies {
		for _, setting := range []string{config.ActionBlock, config.ActionWarn, config.ActionAllow} {
			for _, transport := range []string{"forward", "reverse"} {
				t.Run(body.name+"/"+setting+"/"+transport, func(t *testing.T) {
					t.Parallel()
					parse, opaque := config.ActionAllow, config.ActionAllow
					if body.knob == "parse" {
						parse = setting
					} else {
						opaque = setting
					}
					expect := attackObserve
					if setting == config.ActionBlock {
						expect = attackRefuse
					}
					ex := attackExchange{
						method: http.MethodPost, path: "/v1/items", body: []byte(body.body),
						parse: parse, opaque: opaque,
						rules: func(host string) []config.RequestPolicyRule {
							return []config.RequestPolicyRule{attackRoute(host, http.MethodPost, "/v1/items", config.ActionBlock), attackDisc(host, http.MethodPost, "/v1/items")}
						},
					}
					runAttackPair(t, transport, expect, ex)
				})
			}
		}
	}
}

func TestRequestPolicyAuditAttackGraphQL(t *testing.T) {
	t.Parallel()
	alias := `{"query":"mutation { x: deleteRecord(id: 1) { id } }"}`
	fragment := `{"query":"mutation { ...f } fragment f on Mutation { deleteRecord(id: 1) { id } }"}`
	apq := `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`
	mixed := `[{"query":"mutation { deleteRecord { id } }"},{"query":"mutation { deleteRecord"}]`
	cases := []struct {
		name      string
		body      string
		knob      string
		inspected bool
	}{
		{name: "B1_aliased_root", body: alias, knob: "parse", inspected: true},
		{name: "B2_fragment", body: fragment, knob: "parse", inspected: true},
		{name: "B3_apq", body: apq, knob: "opaque"},
		{name: "B4_one_unparsed", body: mixed, knob: "parse"},
	}
	for _, tc := range cases {
		for _, setting := range []string{config.ActionBlock, config.ActionWarn} {
			for _, transport := range []string{"forward", "reverse"} {
				t.Run(tc.name+"/"+setting+"/"+transport, func(t *testing.T) {
					t.Parallel()
					parse, opaque := config.ActionAllow, config.ActionAllow
					if tc.knob == "parse" {
						parse = setting
					} else {
						opaque = setting
					}
					expect := attackObserve
					if !tc.inspected && setting == config.ActionBlock {
						expect = attackRefuse
					}
					ex := attackExchange{
						method: http.MethodPost, path: "/graphql", body: []byte(tc.body),
						parse: parse, opaque: opaque,
						rules: func(host string) []config.RequestPolicyRule {
							return []config.RequestPolicyRule{
								attackRoute(host, http.MethodPost, "/graphql", config.ActionBlock),
								attackGraphQL(host, http.MethodPost, "/graphql"),
							}
						},
					}
					runAttackPair(t, transport, expect, ex)
				})
			}
		}
	}
}

func TestRequestPolicyAuditAttackBodyTransfer(t *testing.T) {
	t.Parallel()
	plain := []byte(`{"action":"deleteAll"}`)
	gzipped := gzipRequestBody(t, plain)
	deflated := deflateRequestBody(t, plain)
	stacked := gzipRequestBody(t, gzipped)
	overDecoded := bytes.Repeat([]byte("x"), 64)
	overDecoded = append([]byte(`{"action":"deleteAll","pad":"`), overDecoded...)
	overDecoded = append(overDecoded, []byte(`"}`)...)
	gzipOver := gzipRequestBody(t, overDecoded)
	for _, transport := range []string{"forward", "reverse"} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			routeAndDisc := func(host string) []config.RequestPolicyRule {
				return []config.RequestPolicyRule{attackRoute(host, http.MethodPost, "/v1/items", config.ActionBlock), attackDisc(host, http.MethodPost, "/v1/items")}
			}
			routeOnly := func(host string) []config.RequestPolicyRule {
				return []config.RequestPolicyRule{attackRoute(host, http.MethodPost, "/v1/items", config.ActionBlock)}
			}
			t.Run("C_chunked_trailers", func(t *testing.T) {
				t.Parallel()
				_, offBody := runAttackPair(t, transport, attackObserve, attackExchange{
					method: http.MethodPost, path: "/v1/items", body: plain, chunked: true,
					parse: config.ActionAllow, opaque: config.ActionAllow, rules: routeAndDisc,
				})
				if !bytes.Equal(offBody, plain) {
					t.Fatalf("upstream body = %q", offBody)
				}
			})
			t.Run("C_route_only_over_limit_observed", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackObserve, attackExchange{
					method: http.MethodPost, path: "/v1/items", body: bytes.Repeat(plain, 4), maxBody: 8,
					rules: routeOnly,
				})
			})
			t.Run("C_exact_limit", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackObserve, attackExchange{
					method: http.MethodPost, path: "/v1/items", body: plain, maxBody: len(plain),
					parse: config.ActionAllow, opaque: config.ActionAllow, rules: routeAndDisc,
				})
			})
			t.Run("C_one_byte_over", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackRefuse, attackExchange{
					method: http.MethodPost, path: "/v1/items", body: plain, maxBody: len(plain) - 1,
					parse: config.ActionAllow, opaque: config.ActionAllow, rules: routeAndDisc,
				})
			})
			t.Run("C_gzip_decodes", func(t *testing.T) {
				t.Parallel()
				_, offBody := runAttackPair(t, transport, attackObserve, attackExchange{
					method: http.MethodPost, path: "/v1/items", body: gzipped, encoding: "gzip",
					parse: config.ActionAllow, opaque: config.ActionAllow, rules: routeAndDisc,
				})
				if !bytes.Equal(offBody, gzipped) {
					t.Fatalf("upstream saw decoded bytes len=%d want wire %d", len(offBody), len(gzipped))
				}
			})
			t.Run("C_gzip_decoded_over_limit", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackRefuse, attackExchange{
					method: http.MethodPost, path: "/v1/items", body: gzipOver, encoding: "gzip", maxBody: len(gzipOver),
					parse: config.ActionAllow, opaque: config.ActionAllow, rules: routeAndDisc,
				})
			})
			t.Run("C_deflate", func(t *testing.T) {
				t.Parallel()
				_, offBody := runAttackPair(t, transport, attackObserve, attackExchange{
					method: http.MethodPost, path: "/v1/items", body: deflated, encoding: "deflate",
					parse: config.ActionAllow, opaque: config.ActionAllow, rules: routeAndDisc,
				})
				if !bytes.Equal(offBody, deflated) {
					t.Fatalf("upstream saw decoded bytes len=%d want wire %d", len(offBody), len(deflated))
				}
			})
			t.Run("C_stacked_gzip", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackRefuse, attackExchange{
					method: http.MethodPost, path: "/v1/items", body: stacked, encoding: "gzip, gzip",
					parse: config.ActionAllow, opaque: config.ActionAllow, rules: routeAndDisc,
				})
			})
			t.Run("C_empty_declared_gzip", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackObserve, attackExchange{
					method: http.MethodPost, path: "/v1/items", body: []byte{}, encoding: "gzip",
					parse: config.ActionAllow, opaque: config.ActionAllow, rules: routeAndDisc,
				})
			})
		})
	}
}

func attackIntercept(t *testing.T, cfg *config.Config, rawURL string, body []byte, hdr http.Header) policyAuditObs {
	t.Helper()
	p, logs, receipts := policyAuditRig(t, cfg)
	var hits atomic.Int32
	ic := &InterceptContext{
		TargetHost: rpTestHost, TargetPort: "443", Config: cfg, Scanner: p.scannerPtr.Load(),
		Logger: p.logger, Metrics: p.metrics, Proxy: p, RequestID: "audit-attack", ClientIP: "192.0.2.1",
	}
	handler := newInterceptHandler(ic, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/upload" {
			hits.Add(1)
		}
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusOK)
		return rec.Result(), nil
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, rawURL, bytes.NewReader(body))
	req.Host = rpTestHost
	if hdr != nil {
		req.Header = hdr.Clone()
	}
	req.Header.Set(headerContentType, contentTypeJSON)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return policyAuditObs{status: w.Code, upstream: hits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics, receipts: receipts}
}

func attackForwardHTTPS(t *testing.T, cfg *config.Config, body []byte, hdr http.Header) policyAuditObs {
	t.Helper()
	var hits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/upload" {
			hits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	pool := x509.NewCertPool()
	cert := upstream.Certificate()
	if cert == nil {
		t.Fatal("tls server certificate")
	}
	pool.AddCert(cert)
	serverName := "example.com"
	if len(cert.DNSNames) > 0 {
		serverName = cert.DNSNames[0]
	}
	p, logs, receipts := policyAuditRig(t, cfg)
	p.client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == rpTestHost+":443" {
				return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		TLSClientConfig:    &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12},
		DisableCompression: true,
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+rpTestHost+"/v1/upload", bytes.NewReader(body))
	req.Header.Set(headerContentType, contentTypeJSON)
	for name, values := range hdr {
		req.Header[name] = append([]string(nil), values...)
	}
	w := httptest.NewRecorder()
	p.buildHandler(http.NewServeMux()).ServeHTTP(w, req)
	return policyAuditObs{status: w.Code, upstream: hits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics, receipts: receipts}
}

func TestRequestPolicyAuditAttackExcept(t *testing.T) {
	t.Parallel()
	approved := []byte(`{"destinationId":"archive"}`)
	other := []byte(`{"destinationId":"purge"}`)
	dup := []byte(`{"destinationId":"archive","destinationId":"purge"}`)
	target := "https://" + rpTestHost + "/v1/upload"
	rules := func(string) []config.RequestPolicyRule {
		return []config.RequestPolicyRule{attackExact(rpTestHost, http.MethodPost, "/v1/upload", approved)}
	}
	t.Run("D1_match", func(t *testing.T) {
		t.Parallel()
		for _, enforce := range []bool{true, false} {
			cfg := attackConfig(enforce, config.ActionAllow, config.ActionAllow, "", rules("")...)
			on := attackIntercept(t, cfg, target, approved, nil)
			if on.status != http.StatusOK || on.upstream != 1 || strings.Contains(on.logs, "would_block=true") || strings.Contains(on.logs, `"event":"blocked"`) {
				t.Fatalf("intercept enforce=%t status=%d upstream=%d logs=%s", enforce, on.status, on.upstream, on.logs)
			}
			fwd := attackForwardHTTPS(t, cfg, approved, nil)
			if fwd.status != http.StatusOK || fwd.upstream != 1 || strings.Contains(fwd.logs, "would_block=true") || strings.Contains(fwd.logs, `"event":"blocked"`) {
				t.Fatalf("forward enforce=%t status=%d upstream=%d logs=%s", enforce, fwd.status, fwd.upstream, fwd.logs)
			}
		}
	})
	t.Run("D1_reverse_http_does_not_match", func(t *testing.T) {
		t.Parallel()
		// An exact-request exception is canonical https. The reverse handler
		// has no TLS client config, so this http upstream cannot be the
		// approved URL. The resulting marked block is observed.
		runAttackPair(t, "reverse", attackObserve, attackExchange{
			method: http.MethodPost, path: "/v1/upload", body: approved,
			parse: config.ActionAllow, opaque: config.ActionAllow,
			rules: func(host string) []config.RequestPolicyRule {
				rule := attackExact(host, http.MethodPost, "/v1/upload", approved)
				return []config.RequestPolicyRule{rule}
			},
		})
	})
	t.Run("D2_body_differs", func(t *testing.T) {
		t.Parallel()
		for _, transport := range []string{"intercept", "forward"} {
			t.Run(transport, func(t *testing.T) {
				t.Parallel()
				cfgOn := attackConfig(true, config.ActionAllow, config.ActionAllow, "", rules("")...)
				cfgOff := attackConfig(false, config.ActionAllow, config.ActionAllow, "", rules("")...)
				var on, off policyAuditObs
				if transport == "intercept" {
					on = attackIntercept(t, cfgOn, target, other, nil)
					off = attackIntercept(t, cfgOff, target, other, nil)
				} else {
					on = attackForwardHTTPS(t, cfgOn, other, nil)
					off = attackForwardHTTPS(t, cfgOff, other, nil)
				}
				assertAttackPair(t, attackObserve, on, off)
			})
		}
	})
	t.Run("D3_unparseable", func(t *testing.T) {
		t.Parallel()
		body := []byte("not-json")
		for _, transport := range []string{"intercept", "forward"} {
			t.Run(transport, func(t *testing.T) {
				t.Parallel()
				cfgOn := attackConfig(true, config.ActionAllow, config.ActionAllow, "", rules("")...)
				cfgOff := attackConfig(false, config.ActionAllow, config.ActionAllow, "", rules("")...)
				var on, off policyAuditObs
				if transport == "intercept" {
					on = attackIntercept(t, cfgOn, target, body, nil)
					off = attackIntercept(t, cfgOff, target, body, nil)
				} else {
					on = attackForwardHTTPS(t, cfgOn, body, nil)
					off = attackForwardHTTPS(t, cfgOff, body, nil)
				}
				assertAttackPair(t, attackRefuse, on, off)
			})
		}
	})
	t.Run("D4_duplicate_keys", func(t *testing.T) {
		t.Parallel()
		for _, transport := range []string{"intercept", "forward"} {
			t.Run(transport, func(t *testing.T) {
				t.Parallel()
				cfgOn := attackConfig(true, config.ActionAllow, config.ActionAllow, "", rules("")...)
				cfgOff := attackConfig(false, config.ActionAllow, config.ActionAllow, "", rules("")...)
				var on, off policyAuditObs
				if transport == "intercept" {
					on = attackIntercept(t, cfgOn, target, dup, nil)
					off = attackIntercept(t, cfgOff, target, dup, nil)
				} else {
					on = attackForwardHTTPS(t, cfgOn, dup, nil)
					off = attackForwardHTTPS(t, cfgOff, dup, nil)
				}
				assertAttackPair(t, attackRefuse, on, off)
			})
		}
	})
	t.Run("D5_method_override", func(t *testing.T) {
		t.Parallel()
		for _, header := range []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"} {
			t.Run(header, func(t *testing.T) {
				t.Parallel()
				hdr := make(http.Header)
				hdr.Set(header, http.MethodPost)
				cfgOn := attackConfig(true, config.ActionAllow, config.ActionAllow, "", rules("")...)
				cfgOff := attackConfig(false, config.ActionAllow, config.ActionAllow, "", rules("")...)
				on := attackIntercept(t, cfgOn, target, approved, hdr)
				off := attackIntercept(t, cfgOff, target, approved, hdr)
				assertAttackPair(t, attackObserve, on, off)
				fwdOn := attackForwardHTTPS(t, cfgOn, approved, hdr)
				fwdOff := attackForwardHTTPS(t, cfgOff, approved, hdr)
				assertAttackPair(t, attackObserve, fwdOn, fwdOff)
			})
		}
	})
	t.Run("D6_batch_uninspectable", func(t *testing.T) {
		t.Parallel()
		for _, transport := range []string{"forward", "reverse"} {
			t.Run(transport, func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackRefuse, attackExchange{
					method: http.MethodPost, path: "/v1/$batch", body: []byte("{"),
					parse: config.ActionBlock, opaque: config.ActionAllow,
					rules: func(host string) []config.RequestPolicyRule {
						return []config.RequestPolicyRule{attackExact(host, http.MethodPost, "/v1/$batch", approved)}
					},
					batches: func(host string) []config.RequestPolicyBatch { return []config.RequestPolicyBatch{attackBatch(host)} },
				})
			})
		}
	})
}

func TestRequestPolicyAuditAttackBatch(t *testing.T) {
	t.Parallel()
	subUnparsed := []byte(`{"requests":[{"method":"POST","url":"/graphql","body":{"query":"mutation { deleteRecord"}}]}`)
	deep := []byte(`{"requests":[{"method":"POST","url":"/$batch","body":{"requests":[{"method":"POST","url":"/$batch","body":{"requests":[{"method":"POST","url":"/$batch","body":{"requests":[{"method":"POST","url":"/$batch","body":{}}]}}]}}]}}]}`)
	dupKeys := []byte(`{"requests":[],"requests":[]}`)
	badEnvelope := []byte("{")
	for _, transport := range []string{"forward", "reverse"} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			withBatch := func(host string) []config.RequestPolicyBatch { return []config.RequestPolicyBatch{attackBatch(host)} }
			t.Run("E_sub_unparseable_block", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackRefuse, attackExchange{
					method: http.MethodPost, path: "/v1/$batch", body: subUnparsed,
					parse: config.ActionBlock, opaque: config.ActionAllow, batches: withBatch,
					rules: func(host string) []config.RequestPolicyRule {
						return []config.RequestPolicyRule{
							attackRoute(host, http.MethodPost, "/graphql", config.ActionBlock),
							attackGraphQL(host, http.MethodPost, "/graphql"),
						}
					},
				})
			})
			t.Run("E_sub_unparseable_warn", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackObserve, attackExchange{
					method: http.MethodPost, path: "/v1/$batch", body: subUnparsed,
					parse: config.ActionWarn, opaque: config.ActionAllow, batches: withBatch,
					rules: func(host string) []config.RequestPolicyRule {
						return []config.RequestPolicyRule{
							attackRoute(host, http.MethodPost, "/graphql", config.ActionBlock),
							attackGraphQL(host, http.MethodPost, "/graphql"),
						}
					},
				})
			})
			t.Run("E_over_depth", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackRefuse, attackExchange{
					method: http.MethodPost, path: "/v1/$batch", body: deep,
					parse: config.ActionWarn, opaque: config.ActionAllow, batches: withBatch,
					rules: func(host string) []config.RequestPolicyRule {
						return []config.RequestPolicyRule{attackRoute(host, http.MethodPost, "/sendMail", config.ActionBlock)}
					},
				})
			})
			t.Run("E_duplicate_envelope_keys", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackRefuse, attackExchange{
					method: http.MethodPost, path: "/v1/$batch", body: dupKeys,
					parse: config.ActionWarn, opaque: config.ActionAllow, batches: withBatch,
					rules: func(host string) []config.RequestPolicyRule {
						return []config.RequestPolicyRule{attackRoute(host, http.MethodPost, "/sendMail", config.ActionBlock)}
					},
				})
			})
			t.Run("E_bad_envelope_block", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackRefuse, attackExchange{
					method: http.MethodPost, path: "/v1/$batch", body: badEnvelope,
					parse: config.ActionBlock, opaque: config.ActionAllow, batches: withBatch,
					rules: func(host string) []config.RequestPolicyRule {
						return []config.RequestPolicyRule{attackRoute(host, http.MethodPost, "/sendMail", config.ActionBlock)}
					},
				})
			})
			t.Run("E_bad_envelope_warn", func(t *testing.T) {
				t.Parallel()
				runAttackPair(t, transport, attackRelease, attackExchange{
					method: http.MethodPost, path: "/v1/$batch", body: badEnvelope,
					parse: config.ActionWarn, opaque: config.ActionAllow, batches: withBatch,
					rules: func(host string) []config.RequestPolicyRule {
						return []config.RequestPolicyRule{attackRoute(host, http.MethodPost, "/sendMail", config.ActionBlock)}
					},
				})
			})
			t.Run("E_stream_failed", func(t *testing.T) {
				t.Parallel()
				for _, enforce := range []bool{true, false} {
					cfg := attackConfig(enforce, config.ActionAllow, config.ActionBlock, "", attackRoute(rpTestHost, http.MethodPost, "/v1/$batch", config.ActionBlock))
					cfg.RequestPolicy.Batch = []config.RequestPolicyBatch{attackBatch(rpTestHost)}
					p, logs, _ := policyAuditRig(t, cfg)
					req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/v1/$batch", errBody{})
					req.Header.Set(headerContentType, contentTypeJSON)
					w := httptest.NewRecorder()
					p.buildHandler(http.NewServeMux()).ServeHTTP(w, req)
					if w.Code != http.StatusForbidden || !strings.Contains(logs.String(), `"event":"blocked"`) {
						t.Fatalf("enforce=%t status=%d logs=%s", enforce, w.Code, logs.String())
					}
				}
			})
		})
	}
}

func TestRequestPolicyAuditAttackBatchUnread(t *testing.T) {
	t.Parallel()
	// prepareRequestPolicyBody sets BodyRead before apply on forward and
	// reverse, including a nil body. The unread branch is the decision
	// function with BodyRead left false.
	for _, setting := range []string{config.ActionBlock, config.ActionWarn} {
		t.Run(setting, func(t *testing.T) {
			t.Parallel()
			for _, enforce := range []bool{true, false} {
				cfg := attackConfig(enforce, config.ActionAllow, setting, "")
				cfg.RequestPolicy.Batch = []config.RequestPolicyBatch{attackBatch(rpTestHost)}
				p, logs, _ := policyAuditRig(t, cfg)
				res := p.applyRequestPolicy(requestPolicyInput{
					Host: rpTestHost, Method: http.MethodPost, Path: "/v1/$batch",
					Config: cfg, ContentType: contentTypeJSON, Transport: TransportForward,
					Target: "http://" + rpTestHost + "/v1/$batch",
				})
				if setting == config.ActionBlock {
					if !res.Block || res.Observed {
						t.Fatalf("enforce=%t unread = %+v logs=%s", enforce, res, logs.String())
					}
					continue
				}
				if res.Block || res.Observed {
					t.Fatalf("enforce=%t warn unread = %+v logs=%s", enforce, res, logs.String())
				}
			}
		})
	}
}

func TestRequestPolicyAuditAttackMethodOverride(t *testing.T) {
	t.Parallel()
	headers := []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"}
	orders := []struct {
		name     string
		method   string
		override string
		expect   attackExpect
		postAct  string
		opaque   string
	}{
		{name: "F1_post_then_delete", method: http.MethodPost, override: http.MethodDelete, expect: attackRefuse, postAct: config.ActionBlock, opaque: config.ActionBlock},
		{name: "F1_delete_then_post", method: http.MethodDelete, override: http.MethodPost, expect: attackRefuse, postAct: config.ActionBlock, opaque: config.ActionBlock},
		{name: "F2_marked_block_unmarked_warn", method: http.MethodPost, override: http.MethodDelete, expect: attackObserve, postAct: config.ActionBlock, opaque: config.ActionWarn},
		{name: "F3_marked_warn_unmarked_block", method: http.MethodPost, override: http.MethodDelete, expect: attackRefuse, postAct: config.ActionWarn, opaque: config.ActionBlock},
	}
	for _, header := range headers {
		for _, order := range orders {
			for _, transport := range []string{"forward", "reverse"} {
				t.Run(header+"/"+order.name+"/"+transport, func(t *testing.T) {
					t.Parallel()
					runAttackPair(t, transport, order.expect, attackExchange{
						method: order.method, path: "/v1/items", body: []byte("[1]"),
						overrideName: header, overrideValue: order.override,
						parse: config.ActionAllow, opaque: order.opaque,
						rules: func(host string) []config.RequestPolicyRule {
							return []config.RequestPolicyRule{
								attackRoute(host, http.MethodPost, "/v1/items", order.postAct),
								attackDisc(host, http.MethodDelete, "/v1/items"),
							}
						},
					})
				})
			}
		}
	}
}
