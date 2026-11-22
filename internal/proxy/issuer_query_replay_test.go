// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
	"gopkg.in/yaml.v3"
)

const (
	replayFixtureQuery = "work_order_id=380742&caller=field_console&date_from=2026-11-01&date_to=2026-11-30&" +
		"view_mode=summary&status_filter=complete&sort_field=work_order&sort_order=descending&" +
		"region_code=northwest&group_name=maintenance&team_id=2704&include_closed=true"
	replayFixtureAgent = "agent-one"
	replaySeedPath     = "/app/work/orders/complete"
)

func replayFixtureURL(origin, rawQuery string) string {
	return origin + "/app/menu/service%252Forders?mode=update&encoded_params=" + url.QueryEscape(rawQuery)
}

func TestInterceptIssuerQueryReplay(t *testing.T) {
	e := newSameOriginEnv(t, func(c *config.Config) {
		c.FlightRecorder.RequireReceipts = true
		c.Taint.Policy = config.ModePermissive
	})
	e.issue(http.StatusNoContent)
	logs, receipts := e.withRecordedAudit(t)
	origin := "https://" + delegationSourceHost
	replayURL := replayFixtureURL(origin, replayFixtureQuery)
	do := func(method, target, agent string, want int) {
		t.Helper()
		if got := e.do(agent, method, target); got != want {
			t.Fatalf("%s %s status = %d, want %d; audit: %s", method, target, got, want, logs.String())
		}
	}
	do(http.MethodPost, replayURL, replayFixtureAgent, http.StatusForbidden)
	if e.sourceHit.Load() != 0 {
		t.Fatal("pre-evidence request reached the upstream")
	}
	do(http.MethodGet, origin+replaySeedPath+"?"+replayFixtureQuery, replayFixtureAgent, http.StatusNoContent)
	do(http.MethodPost, replayURL, replayFixtureAgent, http.StatusNoContent)

	for _, step := range []struct {
		name, target, agent string
	}{
		{"changed byte", replayFixtureURL(origin, strings.Replace(replayFixtureQuery, "380742", "380743", 1)), replayFixtureAgent},
		{"different session", replayURL, "agent-two"},
		{"different origin", replayFixtureURL("https://elsewhere.vendor.example", replayFixtureQuery), replayFixtureAgent},
		{"subdomain", replayFixtureURL("https://sub."+delegationSourceHost, replayFixtureQuery), replayFixtureAgent},
		{"malformed value", replayURL + "&oops=%ZZ", replayFixtureAgent},
		{"ambiguous delimiter", replayURL + "&other=one;two=three", replayFixtureAgent},
		{"two values", replayURL + "&other=" + url.QueryEscape(replayFixtureQuery), replayFixtureAgent},
		{"another high entropy value", replayURL + "&other=" + issuedTestToken(), replayFixtureAgent},
		{"high entropy query key", replayURL + "&" + issuedTestToken() + "=okay", replayFixtureAgent},
		{"high entropy path", strings.Replace(replayURL, "service%252Forders", issuedTestToken(), 1), replayFixtureAgent},
	} {
		t.Run(step.name, func(t *testing.T) {
			if got := e.do(step.agent, http.MethodPost, step.target); got != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", got)
			}
		})
	}
	if count := strings.Count(logs.String(), `"event":"`+issuerQueryReplayReceiptKey+`"`); count != 1 {
		t.Fatalf("replay allow audit count = %d, want 1", count)
	}
	r := receipts.requireReceipt(t, issuerQueryReplayReceiptKey)
	if r.ActionRecord.Verdict != config.ActionAllow || strings.Contains(r.ActionRecord.Target, "?") ||
		!strings.Contains(string(r.Ext), `"`+issuerQueryReplayReceiptKey+`":"`+string(issuerQueryReplay)+`"`) {
		t.Fatalf("unexpected replay receipt: action=%+v ext=%s", r.ActionRecord, r.Ext)
	}
}

func TestInterceptIssuerQueryReplayNeedsResponse(t *testing.T) {
	for _, outcome := range []string{"blocked by proxy", "never written", "written with no response"} {
		t.Run(outcome, func(t *testing.T) {
			e := newSameOriginEnv(t, nil)
			e.issue(http.StatusNoContent)
			origin := "https://" + delegationSourceHost
			raw := replayFixtureQuery
			want := http.StatusBadGateway
			if outcome == "blocked by proxy" {
				raw += "&extra=" + issuedTestToken()
				want = http.StatusForbidden
			}
			var attempts atomic.Int32
			e.rt = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				attempts.Add(1)
				if outcome == "written with no response" {
					trace := httptrace.ContextClientTrace(req.Context())
					trace.WroteRequest(httptrace.WroteRequestInfo{})
				}
				return nil, errors.New("upstream unavailable")
			})
			if got := e.do(replayFixtureAgent, http.MethodGet, origin+replaySeedPath+"?"+raw); got != want {
				t.Fatalf("seed status = %d, want %d", got, want)
			}
			before := int32(1)
			if outcome == "blocked by proxy" {
				before = 0
			}
			if got := attempts.Load(); got != before {
				t.Fatalf("seed upstream attempts = %d, want %d", got, before)
			}
			if got := e.do(replayFixtureAgent, http.MethodPost, replayFixtureURL(origin, raw)); got != http.StatusForbidden {
				t.Fatalf("replay status = %d, want 403", got)
			}
			if got := attempts.Load(); got != before {
				t.Fatalf("replay upstream attempts = %d, want %d", got, before)
			}
		})
	}
}

func TestIssuerQueryReplayForwardHTTP(t *testing.T) {
	const (
		redirectPath       = "/app/redirect"
		redirectReplayPath = "/app/redirect/replay"
		resetPath          = "/app/reset"
	)
	redirectedQuery := strings.Replace(replayFixtureQuery, "380742", "387777", 1)
	resetQuery := strings.Replace(replayFixtureQuery, "380742", "387778", 1)
	seed := "agent=query-hint&" + replayFixtureQuery
	outbound, err := url.ParseQuery(replayFixtureQuery)
	if err != nil {
		t.Fatal(err)
	}
	var observed atomic.Pointer[string]
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case redirectPath:
			observed.Store(&r.URL.RawQuery)
			http.Redirect(w, r, replaySeedPath+"?"+redirectedQuery, http.StatusFound)
		case redirectReplayPath:
			http.Redirect(w, r, replayFixtureURL("", outbound.Encode()), http.StatusFound)
		case resetPath:
			observed.Store(&r.URL.RawQuery)
			panic(http.ErrAbortHandler)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer upstream.Close()
	for _, tlsEnabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(tlsEnabled), func(t *testing.T) {
			_, p, cleanup := setupForwardProxyWithInstance(t, func(c *config.Config) {
				issuerCookieTestConfig(t, c)
				c.TLSInterception.Enabled = tlsEnabled
				c.DefaultAgentIdentity = "forward-owner"
				c.Taint.Policy = config.ModePermissive
			})
			defer cleanup()
			receipts := newReceiptProxyHelperWithMetrics(t, p.metrics)
			t.Cleanup(func() { _ = receipts.rec.Close() })
			p.receiptEmitterPtr.Store(receipts.emitter)
			do := func(method, target string, want int) {
				t.Helper()
				req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
				w := httptest.NewRecorder()
				p.handleForwardHTTP(w, req)
				if w.Code != want {
					t.Fatalf("%s %s status = %d, want %d", method, target, w.Code, want)
				}
			}
			do(http.MethodPost, replayFixtureURL(upstream.URL, outbound.Encode()), http.StatusForbidden)
			do(http.MethodGet, upstream.URL+redirectReplayPath, http.StatusForbidden)
			do(http.MethodGet, upstream.URL+redirectPath+"?"+seed, http.StatusFound)
			if got := observed.Load(); got == nil || *got != outbound.Encode() {
				t.Fatal("upstream did not receive the exact query after stripping the agent hint")
			}
			do(http.MethodPost, replayFixtureURL(upstream.URL, redirectedQuery), http.StatusForbidden)
			do(http.MethodPost, replayFixtureURL(upstream.URL, seed), http.StatusForbidden)
			do(http.MethodGet, upstream.URL+resetPath+"?"+resetQuery, http.StatusBadGateway)
			if got := observed.Load(); got == nil || *got != resetQuery {
				t.Fatal("request without a response did not reach the upstream")
			}
			do(http.MethodPost, replayFixtureURL(upstream.URL, resetQuery), http.StatusForbidden)
			want, wantRedirect := http.StatusForbidden, http.StatusForbidden
			if tlsEnabled {
				want, wantRedirect = http.StatusNoContent, http.StatusFound
			}
			do(http.MethodGet, upstream.URL+redirectReplayPath, wantRedirect)
			do(http.MethodPost, replayFixtureURL(upstream.URL, outbound.Encode()), want)
			if tlsEnabled {
				r := receipts.requireReceipt(t, issuerQueryReplayReceiptKey)
				if r.ActionRecord.Transport != TransportForward {
					t.Fatalf("replay receipt transport = %q, want forward", r.ActionRecord.Transport)
				}
			}
		})
	}
}

func TestInterceptIssuerQueryReplayReload(t *testing.T) {
	e := newSameOriginEnv(t, nil)
	e.issue(http.StatusNoContent)
	origin := "https://" + delegationSourceHost
	seedURL := origin + replaySeedPath + "?" + replayFixtureQuery
	replayURL := replayFixtureURL(origin, replayFixtureQuery)
	send := e.openTunnel(replayFixtureAgent, delegationSourceHost)
	check := func(request func(string) int, target string, want int) {
		t.Helper()
		if got := request(target); got != want {
			t.Fatalf("%s status = %d, want %d", target, got, want)
		}
	}
	fresh := func(target string) int {
		return e.do(replayFixtureAgent, http.MethodGet, target)
	}
	check(send, seedURL, http.StatusNoContent)
	check(send, replayURL, http.StatusNoContent)
	same := e.cfg.Clone()
	e.reload(same)
	check(send, replayURL, http.StatusNoContent)

	withCanary := same.Clone()
	withCanary.CanaryTokens.Enabled = true
	withCanary.CanaryTokens.Tokens = []config.CanaryToken{{Name: "order-canary", Value: "field_console"}}
	e.reload(withCanary)
	check(fresh, replayURL, http.StatusForbidden)
	e.reload(same.Clone())
	check(send, replayURL, http.StatusNoContent)

	changed := same.Clone()
	changed.DefaultAgentIdentity = "changed-owner"
	e.reload(changed)
	check(send, replayURL, http.StatusForbidden)
	check(fresh, replayURL, http.StatusForbidden)
	e.reload(same.Clone())
	check(fresh, replayURL, http.StatusForbidden)
	check(fresh, seedURL, http.StatusNoContent)
	check(fresh, replayURL, http.StatusNoContent)

	disabled := same.Clone()
	disabled.RequestBodyScanning.IssuerBoundSessionCookies = false
	e.reload(disabled)
	check(fresh, replayURL, http.StatusForbidden)
	e.reload(same.Clone())
	check(fresh, replayURL, http.StatusForbidden)
	check(fresh, seedURL, http.StatusNoContent)
	check(fresh, replayURL, http.StatusNoContent)
}

func TestIssuerQueryReplayStoreBoundaries(t *testing.T) {
	e := newSameOriginEnv(t, nil)
	runtime := e.p.issuerCookieRuntime.Load()
	scope := func(agent, client string, auth envelope.ActorAuth) issuerQueryReplayScope {
		s := e.p.issuerReplayScope(runtime, e.cfg, agent, client, auth)
		s.scheme = schemeHTTPS
		return s
	}
	ip := "192.0.2.1"
	s := scope(replayFixtureAgent, ip, envelope.ActorAuthBound)
	u := &url.URL{Scheme: schemeHTTPS, Host: "api.vendor.example", RawQuery: replayFixtureQuery}
	record := func(s issuerQueryReplayScope, u *url.URL) {
		s.recordResponse(&http.Request{URL: u}, &http.Response{StatusCode: http.StatusNoContent})
	}
	allow := func(s issuerQueryReplayScope, origin *url.URL) bool {
		target := *origin
		target.RawQuery = "replay=" + url.QueryEscape(replayFixtureQuery)
		var used bool
		ctx := s.scanContext(context.Background(), &target, &used)
		return e.sc.Scan(ctx, target.String()).Allowed && used
	}
	record(s, u)
	if !allow(s, u) {
		t.Fatal("expected an exact replay")
	}
	for _, check := range []struct {
		name, scheme, host string
		scope              issuerQueryReplayScope
	}{
		{"scheme", schemeHTTP, u.Host, s},
		{"port", schemeHTTPS, u.Host + ":8443", s},
		{"domain", schemeHTTPS, "other.vendor.example", s},
		{"subdomain", schemeHTTPS, "sub." + u.Host, s},
		{"identity", schemeHTTPS, u.Host, scope("agent-two", ip, envelope.ActorAuthBound)},
		{"client", schemeHTTPS, u.Host, scope(replayFixtureAgent, "192.0.2.2", envelope.ActorAuthBound)},
		{"untrusted", schemeHTTPS, u.Host, scope(replayFixtureAgent, ip, envelope.ActorAuthSelfDeclared)},
	} {
		t.Run(check.name, func(t *testing.T) {
			if allow(check.scope, &url.URL{Scheme: check.scheme, Host: check.host}) {
				t.Fatal("different scope received replay relief")
			}
		})
	}

	for i := range issuerQueryReplayMaxEntries {
		other := *u
		other.RawQuery = fmt.Sprintf("id=%d", i)
		record(s, &other)
	}
	if allow(s, u) {
		t.Fatal("evicted raw query received relief")
	}
	record(s, u)
	for i := range issuerCookieMaxSessions {
		record(scope("agent-"+strconv.Itoa(i), ip, envelope.ActorAuthBound), u)
	}
	if allow(s, u) {
		t.Fatal("evicted session received relief")
	}
}

func TestIssuerQueryReplayPreservesDLP(t *testing.T) {
	e := newSameOriginEnv(t, nil)
	secret := issuerUnissuedSecret()
	u, err := url.Parse(replayFixtureURL("https://"+delegationSourceHost, replayFixtureQuery+"&extra="+secret))
	if err != nil {
		t.Fatal(err)
	}
	ctx := scanner.WithIssuerQueryReplayAllowance(context.Background(), func(string) bool {
		t.Error("query entropy must not precede a URL DLP block")
		return true
	})
	result := e.sc.Scan(ctx, u.String())
	if result.Allowed || result.Scanner != scanner.ScannerCoreDLP {
		t.Fatalf("credential result = %+v, want URL DLP denial", result)
	}
}

func TestIssuerQueryReplaySetting(t *testing.T) {
	for _, tt := range []struct {
		name, yaml string
		want       int
	}{
		{"omitted", "{}", http.StatusNoContent},
		{"null", "issuer_bound_session_cookies: null", http.StatusNoContent},
		{"false", "issuer_bound_session_cookies: false", http.StatusForbidden},
		{"true", "issuer_bound_session_cookies: true", http.StatusNoContent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newSameOriginEnv(t, func(c *config.Config) {
				if err := yaml.Unmarshal([]byte(tt.yaml), &c.RequestBodyScanning); err != nil {
					t.Fatal(err)
				}
			})
			e.issue(http.StatusNoContent)
			origin := "https://" + delegationSourceHost
			seed := origin + replaySeedPath + "?" + replayFixtureQuery
			if got := e.do(replayFixtureAgent, http.MethodGet, seed); got != http.StatusNoContent {
				t.Fatalf("seed status = %d, want 204", got)
			}
			if got := e.do(replayFixtureAgent, http.MethodGet, replayFixtureURL(origin, replayFixtureQuery)); got != tt.want {
				t.Fatalf("replay status = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestInterceptIssuerQueryReplayRevokedBeforeSend pins that replay relief is
// rechecked at dispatch. The URL is relieved, then a reload revokes the replay
// evidence while the request body is still being read; the request must not
// reach the upstream.
func TestInterceptIssuerQueryReplayRevokedBeforeSend(t *testing.T) {
	e := newSameOriginEnv(t, func(c *config.Config) {
		c.RequestBodyScanning.Enabled = true
		c.Taint.Policy = config.ModePermissive
	})
	e.issue(http.StatusNoContent)
	logs, _ := e.withRecordedAudit(t)
	origin := "https://" + delegationSourceHost
	if got := e.do(replayFixtureAgent, http.MethodGet, origin+replaySeedPath+"?"+replayFixtureQuery); got != http.StatusNoContent {
		t.Fatalf("seed status = %d, want 204", got)
	}
	hitsBefore := e.sourceHit.Load()

	bodyReader, bodyWriter := io.Pipe()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, replayFixtureURL(origin, replayFixtureQuery), bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	status := make(chan int, 1)
	cfg, sc, logger, p := e.cfg, e.sc, e.logger, e.p
	go func() {
		resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
			Upstream: e.upstream, TargetHost: delegationSourceHost, TargetPort: "443", UpstreamRT: e.rt,
			Cache: e.cache, Pool: e.pool, Config: cfg, Scanner: sc, Logger: logger, Metrics: e.m,
			Request: req, Proxy: p, Agent: replayFixtureAgent, ActorAuth: envelope.ActorAuthBound,
		})
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		status <- resp.StatusCode
	}()
	// The replay allow is recorded right after the URL rescan, before the
	// body is read, so its audit event marks the window to reload in.
	testwait.For(t, 10*time.Second, func() bool {
		return strings.Contains(logs.String(), `"event":"`+issuerQueryReplayReceiptKey+`"`)
	}, "replay relief was never recorded")
	disabled := cfg.Clone()
	disabled.RequestBodyScanning.IssuerBoundSessionCookies = false
	e.reload(disabled)
	_, _ = io.WriteString(bodyWriter, "note=ready")
	_ = bodyWriter.Close()

	if got := <-status; got != http.StatusForbidden {
		t.Fatalf("revoked replay status = %d, want 403; audit: %s", got, logs.String())
	}
	if got := e.sourceHit.Load(); got != hitsBefore {
		t.Fatalf("revoked replay reached the upstream (%d hits, want %d)", got, hitsBefore)
	}
	if !strings.Contains(logs.String(), issuerQueryReplayStaleLayer) {
		t.Fatalf("stale replay refusal not logged; audit: %s", logs.String())
	}
}

func TestCanonicalReplayPort(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"https://h.vendor.example", "443"},
		{"https://h.vendor.example:443", "443"},
		{"https://h.vendor.example:0443", "443"},
		{"http://h.vendor.example:080", "80"},
		{"http://h.vendor.example:8080", "8080"},
		{"http://h.vendor.example:0", ""},
		{"http://h.vendor.example:65536", ""},
		{"ftp://h.vendor.example", ""},
	} {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := canonicalReplayPort(u); got != tc.want {
			t.Errorf("canonicalReplayPort(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
	scope := issuerQueryReplayScope{scheme: schemeHTTP, runtime: newSameOriginEnv(t, nil).p.issuerCookieRuntime.Load()}
	a, _ := url.Parse("http://h.vendor.example:080/x")
	b, _ := url.Parse("http://h.vendor.example/x")
	da, okA := scope.digest(a, "v")
	db, okB := scope.digest(b, "v")
	if !okA || !okB || da != db {
		t.Fatal("equivalent port spellings must produce the same replay digest")
	}
	if issuerReplayAuthorityMatches(&http.Request{Host: "h.vendor.example:080", URL: b}) != true {
		t.Fatal("Host with a zero-padded default port must match the URL authority")
	}
}
