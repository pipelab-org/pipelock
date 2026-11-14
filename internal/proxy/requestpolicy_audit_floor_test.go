// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"gopkg.in/yaml.v3"
)

const auditFloorJSON = "application/json"

// TestRequestPolicyAuditHiddenFloors refuses an audit-mode request when a
// configured rule block is merged with a floor. A fail-closed action of warn
// or allow leaves the marked rule liftable.
type auditFloorCase struct {
	name     string
	lift     bool
	build    func(host string) *config.Config
	method   string
	path     string
	body     func(t *testing.T) []byte
	encoding string
	override string
	skipBody bool
}

func TestRequestPolicyAuditHiddenFloors(t *testing.T) {
	t.Parallel()
	routeBlock := func(host, method, path string) config.RequestPolicyRule {
		return config.RequestPolicyRule{
			Name: rpRuleName, Action: config.ActionBlock,
			Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{method}, PathPrefixes: []string{path}},
			Reason: "dangerous operation requires operator approval",
		}
	}
	gqlRule := func(host, method, path string) config.RequestPolicyRule {
		return config.RequestPolicyRule{
			Name: "gql-floor", Action: config.ActionBlock,
			Route: config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{method}, PathPrefixes: []string{path}},
			GraphQL: &config.RequestPolicyGraphQL{
				OperationTypes:    []string{"mutation"},
				RootFieldPatterns: []string{`^deleteRecord$`},
			},
		}
	}
	badGraphQL := func(t *testing.T) []byte {
		t.Helper()
		return []byte(`{"query":"mutation { deleteRecord "}`)
	}
	cases := []auditFloorCase{
		{
			name: "graphql parse error",
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
				cfg.RequestPolicy.OnParseError = config.ActionBlock
				return cfg
			},
			method: http.MethodPost, path: "/graphql", body: badGraphQL,
		},
		{
			name: "graphql parse error warns",
			lift: true,
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
				cfg.RequestPolicy.OnParseError = config.ActionWarn
				return cfg
			},
			method: http.MethodPost, path: "/graphql", body: badGraphQL,
		},
		{
			name: "opaque operation",
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
				cfg.RequestPolicy.OnOpaqueOperation = config.ActionBlock
				return cfg
			},
			method: http.MethodPost, path: "/graphql",
			body: func(*testing.T) []byte {
				return []byte(`{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`)
			},
		},
		{
			name: "opaque operation allows",
			lift: true,
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
				cfg.RequestPolicy.OnOpaqueOperation = config.ActionAllow
				return cfg
			},
			method: http.MethodPost, path: "/graphql",
			body: func(*testing.T) []byte {
				return []byte(`{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`)
			},
		},
		{
			name: "except on uninspectable body",
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/v1/upload"), config.RequestPolicyRule{
					Name: "except-floor", Action: config.ActionBlock,
					Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodPost}, PathPrefixes: []string{"/v1/upload"}},
					Except: &config.RequestPolicyException{Field: "destinationId", Values: []string{"archive"}},
				})
				cfg.RequestPolicy.OnParseError = config.ActionAllow
				return cfg
			},
			method: http.MethodPost, path: "/v1/upload",
			body: func(*testing.T) []byte { return []byte("not-json") },
		},
		{
			name: "undecodable default",
			build: func(host string) *config.Config {
				return policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
			},
			method: http.MethodPost, path: "/graphql", encoding: "gzip, gzip",
			body: func(t *testing.T) []byte {
				return gzipRequestBody(t, gzipRequestBody(t, []byte(deleteRecordGraphQLBody())))
			},
		},
		{
			name: "undecodable explicit block",
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
				cfg.RequestPolicy.OnUndecodableEncoding = config.ActionBlock
				return cfg
			},
			method: http.MethodPost, path: "/graphql", encoding: "gzip, gzip",
			body: func(t *testing.T) []byte {
				return gzipRequestBody(t, gzipRequestBody(t, []byte(deleteRecordGraphQLBody())))
			},
		},
		{
			name: "undecodable allows",
			lift: true,
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
				cfg.RequestPolicy.OnUndecodableEncoding = config.ActionAllow
				cfg.RequestPolicy.OnParseError = config.ActionAllow
				cfg.RequestPolicy.OnOpaqueOperation = config.ActionAllow
				return cfg
			},
			method: http.MethodPost, path: "/graphql", encoding: "br",
			body: func(*testing.T) []byte { return []byte(deleteRecordGraphQLBody()) },
		},
		{
			name: "truncated gzip behind route block",
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
				cfg.RequestPolicy.OnUndecodableEncoding = config.ActionBlock
				return cfg
			},
			method: http.MethodPost, path: "/graphql", encoding: "gzip",
			body: func(t *testing.T) []byte {
				b := gzipRequestBody(t, []byte(deleteRecordGraphQLBody()))
				return b[:len(b)-1]
			},
		},
		{
			name: "unsupported coding warns behind route block",
			lift: true,
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
				cfg.RequestPolicy.OnUndecodableEncoding = config.ActionWarn
				return cfg
			},
			method: http.MethodPost, path: "/graphql", encoding: "br",
			body: func(*testing.T) []byte { return []byte(deleteRecordGraphQLBody()) },
		},
		{
			name: "body over limit",
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
				cfg.RequestBodyScanning.MaxBodyBytes = 8
				cfg.RequestPolicy.OnParseError = config.ActionWarn
				return cfg
			},
			method: http.MethodPost, path: "/graphql",
			body: func(*testing.T) []byte { return []byte(deleteRecordGraphQLBody()) },
		},
		{
			name: "body unreadable",
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
				cfg.RequestPolicy.OnParseError = config.ActionAllow
				return cfg
			},
			method: http.MethodPost, path: "/graphql",
			body:     func(*testing.T) []byte { return nil },
			skipBody: true,
		},
		{
			name: "graphql duplicate keys",
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/graphql"), gqlRule(host, http.MethodPost, "/graphql"))
				cfg.RequestPolicy.OnParseError = config.ActionAllow
				return cfg
			},
			method: http.MethodPost, path: "/graphql",
			body: func(*testing.T) []byte {
				return []byte(`{"query":"mutation { deleteRecord { id } }","query":"mutation { ok }"}`)
			},
		},
		{
			name: "batch mixed inspection",
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(
					config.RequestPolicyRule{
						Name: rpRuleName, Action: config.ActionBlock,
						Route: config.RequestPolicyRoute{Hosts: []string{host}, PathPatterns: []string{`/sendMail$`}},
					},
					gqlRule(host, http.MethodPost, "/graphql"),
				)
				cfg.RequestPolicy.OnParseError = config.ActionBlock
				cfg.RequestPolicy.Batch = []config.RequestPolicyBatch{{
					Route:          config.RequestPolicyRoute{Hosts: []string{host}, PathPatterns: []string{`/\$batch$`}},
					RequestsField:  "requests",
					MethodField:    "method",
					URLField:       "url",
					BodyField:      "body",
					MaxSubRequests: 64,
				}}
				return cfg
			},
			method: http.MethodPost, path: "/v1.0/$batch",
			body: func(*testing.T) []byte {
				return []byte(`{"requests":[` +
					`{"method":"POST","url":"/v1.0/me/sendMail","body":{}},` +
					`{"method":"POST","url":"/graphql","body":{"query":"mutation { deleteRecord "}}` +
					`]}`)
			},
		},
		{
			name: "batch parse warns",
			lift: true,
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(
					config.RequestPolicyRule{
						Name: rpRuleName, Action: config.ActionBlock,
						Route: config.RequestPolicyRoute{Hosts: []string{host}, PathPatterns: []string{`/sendMail$`}},
					},
					gqlRule(host, http.MethodPost, "/graphql"),
				)
				cfg.RequestPolicy.OnParseError = config.ActionWarn
				cfg.RequestPolicy.Batch = []config.RequestPolicyBatch{{
					Route:          config.RequestPolicyRoute{Hosts: []string{host}, PathPatterns: []string{`/\$batch$`}},
					RequestsField:  "requests",
					MethodField:    "method",
					URLField:       "url",
					BodyField:      "body",
					MaxSubRequests: 64,
				}}
				return cfg
			},
			method: http.MethodPost, path: "/v1.0/$batch",
			body: func(*testing.T) []byte {
				return []byte(`{"requests":[` +
					`{"method":"POST","url":"/v1.0/me/sendMail","body":{}},` +
					`{"method":"POST","url":"/graphql","body":{"query":"mutation { deleteRecord "}}` +
					`]}`)
			},
		},
		{
			name: "override base marked",
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/v1/jobs/1"), gqlRule(host, http.MethodDelete, "/v1/jobs/1"))
				cfg.RequestPolicy.OnParseError = config.ActionBlock
				return cfg
			},
			method: http.MethodPost, path: "/v1/jobs/1", override: http.MethodDelete, body: badGraphQL,
		},
		{
			name: "override floor first",
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/v1/jobs/1"), gqlRule(host, http.MethodDelete, "/v1/jobs/1"))
				cfg.RequestPolicy.OnParseError = config.ActionBlock
				return cfg
			},
			method: http.MethodDelete, path: "/v1/jobs/1", override: http.MethodPost, body: badGraphQL,
		},
		{
			name: "override floor allows",
			lift: true,
			build: func(host string) *config.Config {
				cfg := policyAuditFloorConfig(routeBlock(host, http.MethodPost, "/v1/jobs/1"), gqlRule(host, http.MethodDelete, "/v1/jobs/1"))
				cfg.RequestPolicy.OnParseError = config.ActionAllow
				return cfg
			},
			method: http.MethodDelete, path: "/v1/jobs/1", override: http.MethodPost, body: badGraphQL,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, transport := range []string{"forward", "reverse"} {
				t.Run(transport, func(t *testing.T) {
					t.Parallel()
					obs := serveAuditFloor(t, transport, tc)
					if tc.lift {
						if obs.status != http.StatusOK || obs.upstream != 1 {
							t.Fatalf("status=%d upstream=%d reason=%q logs=%s", obs.status, obs.upstream, obs.reason, obs.logs)
						}
						if strings.Contains(obs.logs, `"event":"blocked"`) || !strings.Contains(obs.logs, "would_block=true") {
							t.Fatalf("logs=%s", obs.logs)
						}
						return
					}
					if obs.status != http.StatusForbidden || obs.upstream != 0 || obs.reason != "request_policy_deny" {
						t.Fatalf("status=%d upstream=%d reason=%q logs=%s", obs.status, obs.upstream, obs.reason, obs.logs)
					}
					if !strings.Contains(obs.logs, `"block_class":"protective"`) {
						t.Fatalf("logs=%s", obs.logs)
					}
				})
			}
		})
	}
}

func policyAuditFloorConfig(rules ...config.RequestPolicyRule) *config.Config {
	cfg := policyAuditConfig(false, rules...)
	cfg.RequestBodyScanning.Enabled = false
	return cfg
}

func serveAuditFloor(t *testing.T, transport string, tc auditFloorCase) policyAuditObs {
	t.Helper()
	var hits atomic.Int32
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	host := rpTestHost
	if transport == "reverse" {
		host = upstreamURLHost(t, upstream.URL)
	}
	cfg := tc.build(host)
	var body []byte
	if tc.body != nil && !tc.skipBody {
		body = tc.body(t)
	}
	reqBody := io.Reader(bytes.NewReader(body))
	if tc.skipBody {
		reqBody = errBody{}
	}
	hdr := make(http.Header)
	hdr.Set(headerContentType, auditFloorJSON)
	if tc.encoding != "" {
		hdr.Set("Content-Encoding", tc.encoding)
	}
	if tc.override != "" {
		hdr.Set("X-HTTP-Method-Override", tc.override)
	}
	switch transport {
	case "forward":
		p, logs, _ := policyAuditRig(t, cfg)
		installForwardTestDialer(p, upstream.Listener.Addr().String())
		req := httptest.NewRequestWithContext(t.Context(), tc.method, "http://"+rpTestHost+tc.path, reqBody)
		req.Header = hdr
		w := httptest.NewRecorder()
		p.buildHandler(http.NewServeMux()).ServeHTTP(w, req)
		return policyAuditObs{status: w.Code, upstream: hits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics}
	case "reverse":
		p, logs, _ := policyAuditRig(t, cfg)
		parsed, err := url.Parse(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		handler := NewReverseProxy(parsed, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
		handler.SetRequestPolicyFn(p.ApplyRequestPolicy)
		handler.SetRequestPolicyPrepareFn(p.PrepareRequestPolicyBody)
		req := httptest.NewRequestWithContext(t.Context(), tc.method, "http://"+rpTestHost+tc.path, reqBody)
		req.Host = rpTestHost
		req.Header = hdr
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return policyAuditObs{status: w.Code, upstream: hits.Load(), reason: w.Header().Get("X-Pipelock-Block-Reason"), logs: logs.String(), metrics: p.metrics}
	default:
		t.Fatalf("transport %s", transport)
		return policyAuditObs{}
	}
}

func TestRequestPolicyAuditModeMatrix(t *testing.T) {
	t.Parallel()
	docs := []struct {
		name    string
		doc     string
		wantNil bool
		audit   bool
	}{
		{name: "omitted", doc: "version: 1\n", wantNil: true},
		{name: "null", doc: "version: 1\nenforce: null\n", wantNil: true},
		{name: "blank", doc: "version: 1\nenforce:\n", wantNil: true},
		{name: "explicit false", doc: "version: 1\nenforce: false\n", audit: true},
		{name: "explicit true", doc: "version: 1\nenforce: true\n"},
	}
	for _, tc := range docs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var parsed config.Config
			if err := yaml.Unmarshal([]byte(tc.doc), &parsed); err != nil {
				t.Fatal(err)
			}
			if tc.wantNil != (parsed.Enforce == nil) {
				t.Fatalf("enforce nil=%v", parsed.Enforce == nil)
			}
			if parsed.Enforce != nil && *parsed.Enforce != !tc.audit {
				t.Fatalf("enforce=%v", *parsed.Enforce)
			}
			cfg := policyAuditConfig(!tc.audit, blockRule(http.MethodDelete))
			cfg.Enforce = parsed.Enforce
			p, logs, _ := policyAuditRig(t, cfg)
			res := p.applyRequestPolicy(auditDecisionInput(cfg))
			assertAuditDecision(t, tc.audit, res, logs.String())
		})
	}
}

func TestRequestPolicyAuditModeKeepsAdmittedConfig(t *testing.T) {
	t.Parallel()
	admitted := policyAuditConfig(false, blockRule(http.MethodDelete))
	p, logs, _ := policyAuditRig(t, admitted)
	live := policyAuditConfig(true, blockRule(http.MethodDelete))
	liveScanner := scanner.MustNew(live)
	t.Cleanup(liveScanner.Close)
	if !p.Reload(live, liveScanner) {
		t.Fatal("reload to enforce")
	}
	res := p.applyRequestPolicy(auditDecisionInput(admitted))
	assertAuditDecision(t, true, res, logs.String())

	back := policyAuditConfig(false, blockRule(http.MethodDelete))
	backScanner := scanner.MustNew(back)
	t.Cleanup(backScanner.Close)
	if !p.Reload(back, backScanner) {
		t.Fatal("reload to audit")
	}
	enforced := p.applyRequestPolicy(auditDecisionInput(live))
	if !enforced.Block || enforced.Observed {
		t.Fatalf("admitted enforce true followed live audit: %+v", enforced)
	}
	same := policyAuditConfig(false, blockRule(http.MethodDelete))
	sameScanner := scanner.MustNew(same)
	t.Cleanup(sameScanner.Close)
	if !p.Reload(same, sameScanner) {
		t.Fatal("reload without change")
	}
	again := p.applyRequestPolicy(auditDecisionInput(admitted))
	if !again.Observed {
		t.Fatalf("unchanged audit admission = %+v", again)
	}
	refused := p.applyRequestPolicy(auditDecisionInput(nil))
	if !refused.Block || refused.Observed {
		t.Fatalf("nil config = %+v", refused)
	}
}

func TestRequestPolicyAuditModeShadowWarnDisabled(t *testing.T) {
	t.Parallel()
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce=%t", enforce), func(t *testing.T) {
			t.Parallel()
			warn := blockRule(http.MethodDelete)
			warn.Action = config.ActionWarn
			shadow := blockRule(http.MethodDelete)
			shadow.Shadow = true
			for _, tc := range []struct {
				name string
				rule config.RequestPolicyRule
				off  bool
			}{
				{name: "warn", rule: warn},
				{name: "shadow", rule: shadow},
				{name: "disabled", off: true, rule: blockRule(http.MethodDelete)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					cfg := policyAuditConfig(enforce, tc.rule)
					if tc.off {
						cfg.RequestPolicy.Enabled = false
					}
					p, logs, _ := policyAuditRig(t, cfg)
					res := p.applyRequestPolicy(auditDecisionInput(cfg))
					if res.Block || res.Observed {
						t.Fatalf("result=%+v logs=%s", res, logs.String())
					}
					if strings.Contains(logs.String(), "would_block=true") {
						t.Fatalf("logs=%s", logs.String())
					}
					if tc.off {
						if logs.String() != "" && strings.Contains(logs.String(), "request_policy") {
							t.Fatalf("disabled section logged %s", logs.String())
						}
						return
					}
					if !strings.Contains(logs.String(), "shadow=") || strings.Contains(logs.String(), `"event":"blocked"`) {
						t.Fatalf("logs=%s", logs.String())
					}
				})
			}
		})
	}
}

func TestRequestPolicyAuditModeLaterFloors(t *testing.T) {
	t.Parallel()
	t.Run("contract", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(backend.Close)
		cfg := policyAuditConfig(false, blockRule(http.MethodDelete))
		p, logs, _ := policyAuditRig(t, cfg)
		p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, contractruntimetest.HTTPEnforceRule("r-other", "other.example.com", "/v1", http.MethodPost)))
		installForwardTestDialer(p, backend.Listener.Addr().String())
		req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "http://"+rpTestHost+"/v1/jobs/1", nil)
		req.Header.Set(AgentHeader, "agent-a")
		w := httptest.NewRecorder()
		p.buildHandler(http.NewServeMux()).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || hits.Load() != 0 {
			t.Fatalf("status=%d hits=%d logs=%s", w.Code, hits.Load(), logs.String())
		}
		if w.Header().Get(blockreason.HeaderReason) != contractDefaultDenyReason || !strings.Contains(logs.String(), "would_block=true") {
			t.Fatalf("reason=%q logs=%s", w.Header().Get(blockreason.HeaderReason), logs.String())
		}
	})
	t.Run("kill switch", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/secret" {
				hits.Add(1)
			}
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(backend.Close)
		host := upstreamURLHost(t, backend.URL)
		cfg := policyAuditConfig(false, config.RequestPolicyRule{
			Name: rpRuleName, Action: config.ActionBlock,
			Route:  config.RequestPolicyRoute{Hosts: []string{host}, Methods: []string{http.MethodGet}},
			Reason: "dangerous operation requires operator approval",
		})
		cfg.KillSwitch.Enabled = true
		p, logs, _ := policyAuditRig(t, cfg)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+backend.URL+"/v1/secret", nil)
		w := httptest.NewRecorder()
		p.handleFetch(w, req)
		if w.Code == http.StatusOK || hits.Load() != 0 || !strings.Contains(logs.String(), "would_block=true") {
			t.Fatalf("status=%d hits=%d logs=%s", w.Code, hits.Load(), logs.String())
		}
		if !strings.Contains(logs.String(), "kill_switch") {
			t.Fatalf("logs=%s", logs.String())
		}
	})
	t.Run("dial ssrf", func(t *testing.T) {
		t.Parallel()
		cfg := policyAuditConfig(false, config.RequestPolicyRule{
			Name: rpRuleName, Action: config.ActionBlock,
			Route:  config.RequestPolicyRoute{Hosts: []string{"rebind.test"}, Methods: []string{http.MethodGet}},
			Reason: "dangerous operation requires operator approval",
		})
		cfg.Internal = []string{"127.0.0.0/8"}
		cfg.DNS.HostOverrides = map[string][]string{"rebind.test": {"203.0.113.10"}}
		p, logs, _ := policyAuditRig(t, cfg)
		p.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			ip := net.ParseIP("127.0.0.1")
			return nil, newSSRFDialBlockError(req.Context(), req.URL.Hostname(), ip, ssrfDialBlockDetail(req.URL.Hostname(), ip))
		})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url=http://rebind.test/v1/secret", nil)
		w := httptest.NewRecorder()
		p.handleFetch(w, req)
		if w.Code != http.StatusForbidden || !strings.Contains(logs.String(), "would_block=true") {
			t.Fatalf("status=%d reason=%q logs=%s", w.Code, w.Header().Get(blockreason.HeaderReason), logs.String())
		}
	})
}

func auditDecisionInput(cfg *config.Config) requestPolicyInput {
	return requestPolicyInput{
		Host: rpTestHost, Method: http.MethodDelete, Path: "/v1/jobs/1",
		Config: cfg, Transport: TransportForward, Target: "http://" + rpTestHost + "/v1/jobs/1",
	}
}

func assertAuditDecision(t *testing.T, audit bool, res requestPolicyResult, logs string) {
	t.Helper()
	if audit {
		if !res.Observed || res.Block || !strings.Contains(logs, "would_block=true") || strings.Contains(logs, `"event":"blocked"`) {
			t.Fatalf("result=%+v logs=%s", res, logs)
		}
		return
	}
	if !res.Block || res.Observed || !strings.Contains(logs, `"event":"blocked"`) {
		t.Fatalf("result=%+v logs=%s", res, logs)
	}
}
