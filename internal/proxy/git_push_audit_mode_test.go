// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"gopkg.in/yaml.v3"
)

const (
	gitPushHost  = "git.vendor.example"
	gitPushForge = "forge.vendor.example"
	gitPushPack  = "/acme/public.git/git-receive-pack"
	gitPushAllow = "/acme/private.git/git-receive-pack"
)

func gitPushAuditConfig(enforce bool) *config.Config {
	cfg := reqPolicyConfig()
	cfg.RequestPolicy.Enabled = false
	cfg.RequestPolicy.Rules = nil
	flag := enforce
	cfg.Enforce = &flag
	cfg.GitProtection.Enabled = true
	cfg.GitProtection.AllowedPushRepos = []string{gitPushHost + "/acme/private"}
	return cfg
}

func gitPushURL(path string) string {
	return "http://" + gitPushHost + path
}

func installGitPushDialer(p *Proxy, backend string) {
	p.client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			switch addr {
			case gitPushHost + ":80", gitPushForge + ":80", "169.254.169.254:80":
				return (&net.Dialer{}).DialContext(ctx, network, backend)
			default:
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}
		},
		DisableCompression: true,
	}
}

func gitPushSession(t *testing.T, p *Proxy, cfg *config.Config) *SessionState {
	t.Helper()
	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("session manager missing")
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, gitPushURL(gitPushPack), nil)
	req.RemoteAddr = "192.0.2.1:1234"
	_, id := p.editionPtr.Load().ResolveAgent(req.Context(), req)
	agent := id.Name
	if agent == "" {
		agent = agentAnonymous
	}
	sess := sm.GetOrCreate(responseTaintSessionKey(cfg, agent, "192.0.2.1", id.Auth))
	if sess == nil {
		t.Fatal("session missing")
	}
	return sess
}

type gitPushObs struct {
	status   int
	reason   string
	upstream int32
	logs     string
	metrics  *Proxy
	receipts *receiptProxyHelper
}

func assertGitPushAudit(t *testing.T, enforce bool, got gitPushObs) {
	t.Helper()
	reasons := gitPushAnomalyReasons(t, got.logs)
	if enforce {
		if got.status != http.StatusForbidden || got.upstream != 0 {
			t.Fatalf("status=%d upstream=%d logs=%s", got.status, got.upstream, got.logs)
		}
		if got.reason != string(blockreason.RequestPolicyDeny) {
			t.Fatalf("reason=%q", got.reason)
		}
		if !strings.Contains(got.logs, `"event":"blocked"`) || !strings.Contains(got.logs, `"block_class":"protective"`) {
			t.Fatalf("logs=%s", got.logs)
		}
		if len(reasons) != 0 {
			t.Fatalf("enforce logged an observation: %v", reasons)
		}
		if count := gitPushActionCount(t, got.metrics); count != 0 {
			t.Fatalf("audit metric=%v", count)
		}
		if got.receipts != nil && !auditBlockReceipt(t, got.receipts) {
			t.Fatal("missing block receipt")
		}
		return
	}
	if got.status != http.StatusOK || got.upstream != 1 {
		t.Fatalf("status=%d upstream=%d reason=%q logs=%s", got.status, got.upstream, got.reason, got.logs)
	}
	if got.reason != "" {
		t.Fatalf("block reason=%q", got.reason)
	}
	if strings.Contains(got.logs, `"event":"blocked"`) {
		t.Fatalf("observed block wrote blocked: %s", got.logs)
	}
	if len(reasons) != 1 || reasons[0] != gitPushAllowlistReason+requestPolicyWouldBlockSuffix {
		t.Fatalf("anomaly reasons=%v", reasons)
	}
	if strings.Contains(reasons[0], "redirect from") || strings.Contains(reasons[0], gitPushHost) {
		t.Fatalf("anomaly detail is not the fixed reason: %q", reasons[0])
	}
	if count := gitPushActionCount(t, got.metrics); count != 1 {
		t.Fatalf("audit metric=%v", count)
	}
	if got.receipts != nil && auditBlockReceipt(t, got.receipts) {
		t.Fatal("observed block wrote a block receipt")
	}
}

func gitPushAnomalyReasons(t *testing.T, logs string) []string {
	t.Helper()
	var reasons []string
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, `"event":"anomaly"`) {
			continue
		}
		var ev struct {
			Scanner string `json:"scanner"`
			Reason  string `json:"reason"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("anomaly json: %v line=%s", err, line)
		}
		if ev.Scanner == scanner.AuditGitProtection {
			reasons = append(reasons, ev.Reason)
		}
	}
	return reasons
}

func gitPushActionCount(t *testing.T, p *Proxy) float64 {
	t.Helper()
	if p == nil || p.metrics == nil {
		t.Fatal("metrics missing")
	}
	families, err := p.metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	for _, family := range families {
		if family.GetName() != "pipelock_git_push_decisions_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricHasLabel(metric, "action", requestPolicyAuditAction) {
				total += metric.GetCounter().GetValue()
			}
		}
	}
	return total
}

func serveGitPushForward(t *testing.T, p *Proxy, rawURL, body string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, rawURL, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.1:1234"
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	w := httptest.NewRecorder()
	p.buildHandler(http.NewServeMux()).ServeHTTP(w, req)
	return w
}

func gitPushRoundTrip(hits *atomic.Int32) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "git-receive-pack") {
			hits.Add(1)
		}
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.WriteString("ok")
		return rec.Result(), nil
	})
}

func serveGitPushIntercept(t *testing.T, p *Proxy, cfg *config.Config, rawURL, body string, rt http.RoundTripper, prepare func(*InterceptContext)) *httptest.ResponseRecorder {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host := parsed.Hostname()
	var hits atomic.Int32
	if rt == nil {
		rt = gitPushRoundTrip(&hits)
	}
	ic := &InterceptContext{
		TargetHost: host,
		TargetPort: "443",
		Config:     cfg,
		Scanner:    p.scannerPtr.Load(),
		Logger:     p.logger,
		Metrics:    p.metrics,
		Proxy:      p,
		RequestID:  "git-push-audit",
		ClientIP:   "192.0.2.1",
		Agent:      agentAnonymous,
	}
	if prepare != nil {
		prepare(ic)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, rawURL, strings.NewReader(body))
	req.Host = host + ":443"
	req.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	newInterceptHandler(ic, rt).ServeHTTP(w, req)
	return w
}

func TestGitPushAllowlistMark(t *testing.T) {
	t.Parallel()
	push := func(raw string) *url.URL {
		t.Helper()
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	mismatch := push("https://" + gitPushHost + gitPushPack)
	allowed := push("https://" + gitPushHost + gitPushAllow)
	cases := []struct {
		name   string
		cfg    config.GitProtection
		method string
		url    *url.URL
		block  bool
		marked bool
	}{
		{
			name:   "configured mismatch",
			cfg:    config.GitProtection{Enabled: true, AllowedPushRepos: []string{gitPushHost + "/acme/private"}},
			method: http.MethodPost, url: mismatch, block: true, marked: true,
		},
		{
			name:   "allowlisted",
			cfg:    config.GitProtection{Enabled: true, AllowedPushRepos: []string{gitPushHost + "/acme/private"}},
			method: http.MethodPost, url: allowed,
		},
		{
			name:   "empty allowlist",
			cfg:    config.GitProtection{Enabled: true},
			method: http.MethodPost, url: mismatch, block: true,
		},
		{
			name:   "blank patterns",
			cfg:    config.GitProtection{Enabled: true, AllowedPushRepos: []string{" ", "\t"}},
			method: http.MethodPost, url: mismatch, block: true,
		},
		{
			name:   "pattern cannot be evaluated",
			cfg:    config.GitProtection{Enabled: true, AllowedPushRepos: []string{"["}},
			method: http.MethodPost, url: mismatch, block: true,
		},
		{
			// The malformed class sits after a literal that already failed
			// to match, so the matcher alone never reports it.
			name:   "malformed tail after a failed literal",
			cfg:    config.GitProtection{Enabled: true, AllowedPushRepos: []string{gitPushHost + "/acme/private*["}},
			method: http.MethodPost, url: mismatch, block: true,
		},
		{
			name:   "bad pattern does not hide a match",
			cfg:    config.GitProtection{Enabled: true, AllowedPushRepos: []string{"[", gitPushHost + "/acme/private"}},
			method: http.MethodPost, url: allowed,
		},
		{
			name:   "disabled",
			cfg:    config.GitProtection{Enabled: false, AllowedPushRepos: []string{gitPushHost + "/acme/private"}},
			method: http.MethodPost, url: mismatch,
		},
		{
			name:   "not a push method",
			cfg:    config.GitProtection{Enabled: true, AllowedPushRepos: []string{gitPushHost + "/acme/private"}},
			method: http.MethodGet, url: mismatch,
		},
		{
			name:   "nil url",
			cfg:    config.GitProtection{Enabled: true, AllowedPushRepos: []string{gitPushHost + "/acme/private"}},
			method: http.MethodPost,
		},
		{
			name:   "not a smart http push",
			cfg:    config.GitProtection{Enabled: true, AllowedPushRepos: []string{gitPushHost + "/acme/private"}},
			method: http.MethodPost, url: push("https://" + gitPushHost + "/acme/public"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := evaluateGitPushAllowlist(tc.cfg, tc.method, tc.url)
			if got.Block != tc.block || got.AllowlistMismatch != tc.marked {
				t.Fatalf("decision=%+v want block=%v marked=%v", got, tc.block, tc.marked)
			}
			if got.Block && got.Reason != gitPushAllowlistReason {
				t.Fatalf("reason=%q", got.Reason)
			}
		})
	}
}

func TestGitPushAuditLiftRefusesWithoutBothAuditConfigs(t *testing.T) {
	t.Parallel()
	markedURL, err := url.Parse("https://" + gitPushHost + gitPushPack)
	if err != nil {
		t.Fatal(err)
	}
	markedCfg := config.GitProtection{Enabled: true, AllowedPushRepos: []string{gitPushHost + "/acme/private"}}
	marked := evaluateGitPushAllowlist(markedCfg, http.MethodPost, markedURL)
	if !marked.Block || !marked.AllowlistMismatch {
		t.Fatalf("decision=%+v", marked)
	}
	empty := evaluateGitPushAllowlist(config.GitProtection{Enabled: true}, http.MethodPost, markedURL)
	if !empty.Block || empty.AllowlistMismatch {
		t.Fatalf("empty decision=%+v", empty)
	}

	admitted := gitPushAuditConfig(false)
	p, logs, _ := policyAuditRig(t, admitted)
	block, observed := p.refuseGitPushAllowlist(admitted, p.logger, audit.LogContext{}, marked, marked.Reason)
	if block || !observed || gitPushActionCount(t, p) != 1 {
		t.Fatalf("both audit block=%v observed=%v logs=%s", block, observed, logs.String())
	}

	var bare *Proxy
	block, observed = bare.refuseGitPushAllowlist(admitted, p.logger, audit.LogContext{}, marked, marked.Reason)
	if !block || observed {
		t.Fatalf("nil proxy block=%v observed=%v", block, observed)
	}
	liveMissing := &Proxy{logger: p.logger}
	block, observed = liveMissing.refuseGitPushAllowlist(admitted, p.logger, audit.LogContext{}, marked, marked.Reason)
	if !block || observed {
		t.Fatalf("nil live block=%v observed=%v", block, observed)
	}
	block, observed = p.refuseGitPushAllowlist(nil, p.logger, audit.LogContext{}, marked, marked.Reason)
	if !block || observed {
		t.Fatalf("nil admitted block=%v observed=%v", block, observed)
	}
	enforced := gitPushAuditConfig(true)
	block, observed = p.refuseGitPushAllowlist(enforced, p.logger, audit.LogContext{}, marked, marked.Reason)
	if !block || observed {
		t.Fatalf("admitted enforce block=%v observed=%v", block, observed)
	}
	attackFlipEnforce(t, p, true)
	block, observed = p.refuseGitPushAllowlist(admitted, p.logger, audit.LogContext{}, marked, marked.Reason)
	if !block || observed {
		t.Fatalf("live enforce block=%v observed=%v", block, observed)
	}
	block, observed = p.refuseGitPushAllowlist(admitted, p.logger, audit.LogContext{}, empty, empty.Reason)
	if !block || observed {
		t.Fatalf("unmarked block=%v observed=%v", block, observed)
	}
}

func TestGitPushAuditModeTransports(t *testing.T) {
	t.Parallel()
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("forward/enforce=%t", enforce), func(t *testing.T) {
			t.Parallel()
			assertGitPushAudit(t, enforce, runGitPushForward(t, enforce, gitPushURL(gitPushPack), "0000"))
		})
		t.Run(fmt.Sprintf("intercept/enforce=%t", enforce), func(t *testing.T) {
			t.Parallel()
			assertGitPushAudit(t, enforce, runGitPushIntercept(t, enforce))
		})
		t.Run(fmt.Sprintf("redirect/enforce=%t", enforce), func(t *testing.T) {
			t.Parallel()
			got := runGitPushRedirect(t, enforce, false)
			if enforce {
				if got.status != http.StatusForbidden || got.initial != 1 || got.final != 0 {
					t.Fatalf("status=%d initial=%d final=%d logs=%s", got.status, got.initial, got.final, got.logs)
				}
				if got.reason != string(blockreason.RedirectScanDenied) {
					t.Fatalf("reason=%q", got.reason)
				}
				if !strings.Contains(got.logs, `"block_class":"protective"`) || len(gitPushAnomalyReasons(t, got.logs)) != 0 {
					t.Fatalf("logs=%s", got.logs)
				}
				if !auditBlockReceipt(t, got.receipts) {
					t.Fatal("missing block receipt")
				}
				return
			}
			// A forward proxy admits the redirect, then returns it to the client.
			// Audit mode delivers that 307. It does not dial the redirected push.
			if got.status != http.StatusTemporaryRedirect || got.initial != 1 || got.final != 0 || got.reason != "" {
				t.Fatalf("status=%d initial=%d final=%d reason=%q logs=%s", got.status, got.initial, got.final, got.reason, got.logs)
			}
			reasons := gitPushAnomalyReasons(t, got.logs)
			if len(reasons) != 1 || reasons[0] != gitPushAllowlistReason+requestPolicyWouldBlockSuffix || strings.Contains(got.logs, `"event":"blocked"`) {
				t.Fatalf("logs=%s", got.logs)
			}
			if gitPushActionCount(t, got.proxy) != 1 {
				t.Fatalf("audit metric missing: %s", got.logs)
			}
			if auditBlockReceipt(t, got.receipts) {
				t.Fatal("observed redirect wrote a block receipt")
			}
		})
	}
}

type gitPushRedirectObs struct {
	status   int
	reason   string
	initial  int32
	final    int32
	logs     string
	receipts *receiptProxyHelper
	proxy    *Proxy
}

func runGitPushForward(t *testing.T, enforce bool, rawURL, body string) gitPushObs {
	t.Helper()
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			hits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(backend.Close)
	cfg := gitPushAuditConfig(enforce)
	p, logs, receipts := policyAuditRig(t, cfg)
	installGitPushDialer(p, backend.Listener.Addr().String())
	w := serveGitPushForward(t, p, rawURL, body, nil)
	return gitPushObs{status: w.Code, reason: w.Header().Get(blockreason.HeaderReason), upstream: hits.Load(), logs: logs.String(), metrics: p, receipts: receipts}
}

func runGitPushIntercept(t *testing.T, enforce bool) gitPushObs {
	t.Helper()
	var hits atomic.Int32
	cfg := gitPushAuditConfig(enforce)
	p, logs, receipts := policyAuditRig(t, cfg)
	w := serveGitPushIntercept(t, p, cfg, "https://"+gitPushHost+gitPushPack, "0000", gitPushRoundTrip(&hits), nil)
	return gitPushObs{status: w.Code, reason: w.Header().Get(blockreason.HeaderReason), upstream: hits.Load(), logs: logs.String(), metrics: p, receipts: receipts}
}

func runGitPushRedirect(t *testing.T, enforce bool, publicRule bool) gitPushRedirectObs {
	t.Helper()
	var initial, final atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == gitPushAllow && r.URL.RawQuery == "" {
			initial.Add(1)
			http.Redirect(w, r, "http://"+gitPushHost+gitPushPack, http.StatusTemporaryRedirect)
			return
		}
		final.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	cfg := gitPushAuditConfig(enforce)
	if publicRule {
		// The redirect hop is the only one whose path matches. Its body is not
		// JSON, so the discriminator cannot be evaluated and stays unmarked.
		cfg.RequestPolicy.Enabled = true
		cfg.RequestPolicy.Rules = []config.RequestPolicyRule{attackDisc(gitPushHost, http.MethodPost, "/acme/public.git/")}
	}
	p, logs, receipts := policyAuditRig(t, cfg)
	installGitPushDialer(p, backend.Listener.Addr().String())
	w := serveGitPushForward(t, p, gitPushURL(gitPushAllow), "0000", nil)
	return gitPushRedirectObs{status: w.Code, reason: w.Header().Get(blockreason.HeaderReason), initial: initial.Load(), final: final.Load(), logs: logs.String(), receipts: receipts, proxy: p}
}

func TestGitPushAuditModeCouldNotDetermine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		repos []string
	}{
		{name: "empty allowlist"},
		{name: "blank patterns", repos: []string{" ", "\t"}},
		{name: "pattern error", repos: []string{"["}},
	}
	for _, enforce := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s/enforce=%t", tc.name, enforce), func(t *testing.T) {
				t.Parallel()
				for _, transport := range []string{"forward", "intercept"} {
					t.Run(transport, func(t *testing.T) {
						t.Parallel()
						cfg := gitPushAuditConfig(enforce)
						cfg.GitProtection.AllowedPushRepos = tc.repos
						var hits atomic.Int32
						backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
							hits.Add(1)
							w.WriteHeader(http.StatusOK)
						}))
						t.Cleanup(backend.Close)
						p, logs, receipts := policyAuditRig(t, cfg)
						var w *httptest.ResponseRecorder
						if transport == "forward" {
							installGitPushDialer(p, backend.Listener.Addr().String())
							w = serveGitPushForward(t, p, gitPushURL(gitPushPack), "0000", nil)
						} else {
							w = serveGitPushIntercept(t, p, cfg, "https://"+gitPushHost+gitPushPack, "0000", gitPushRoundTrip(&hits), nil)
						}
						if w.Code != http.StatusForbidden || hits.Load() != 0 {
							t.Fatalf("status=%d hits=%d logs=%s", w.Code, hits.Load(), logs.String())
						}
						if w.Header().Get(blockreason.HeaderReason) != string(blockreason.RequestPolicyDeny) {
							t.Fatalf("reason=%q", w.Header().Get(blockreason.HeaderReason))
						}
						if !strings.Contains(logs.String(), `"event":"blocked"`) || !strings.Contains(logs.String(), `"block_class":"protective"`) {
							t.Fatalf("logs=%s", logs.String())
						}
						if len(gitPushAnomalyReasons(t, logs.String())) != 0 || gitPushActionCount(t, p) != 0 {
							t.Fatalf("unmarked refusal was observed: %s", logs.String())
						}
						if !auditBlockReceipt(t, receipts) {
							t.Fatal("missing block receipt")
						}
					})
				}
			})
		}
	}
}

func TestGitPushAuditModeHiddenFloors(t *testing.T) {
	t.Parallel()
	credential := "AKIA" + "IOSFODNN7EXAMPLE"
	t.Run("forward/body dlp", func(t *testing.T) {
		t.Parallel()
		got := runGitPushForward(t, false, gitPushURL(gitPushPack), "token="+credential)
		if got.status != http.StatusForbidden || got.upstream != 0 || got.reason != string(blockreason.DLPMatch) {
			t.Fatalf("status=%d upstream=%d reason=%q logs=%s", got.status, got.upstream, got.reason, got.logs)
		}
		if len(gitPushAnomalyReasons(t, got.logs)) != 1 || !strings.Contains(got.logs, `"event":"blocked"`) {
			t.Fatalf("logs=%s", got.logs)
		}
	})
	t.Run("forward/url credential", func(t *testing.T) {
		t.Parallel()
		got := runGitPushForward(t, false, gitPushURL(gitPushPack)+"?token="+credential, "0000")
		if got.status != http.StatusForbidden || got.upstream != 0 || got.reason != string(blockreason.DLPMatch) || len(gitPushAnomalyReasons(t, got.logs)) != 0 {
			t.Fatalf("status=%d upstream=%d reason=%q logs=%s", got.status, got.upstream, got.reason, got.logs)
		}
	})
	t.Run("forward/kill switch", func(t *testing.T) {
		t.Parallel()
		cfg := gitPushAuditConfig(false)
		cfg.KillSwitch.Enabled = true
		var hits atomic.Int32
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(backend.Close)
		p, logs, _ := policyAuditRig(t, cfg)
		installGitPushDialer(p, backend.Listener.Addr().String())
		w := serveGitPushForward(t, p, gitPushURL(gitPushPack), "0000", nil)
		if w.Code == http.StatusOK || hits.Load() != 0 || len(gitPushAnomalyReasons(t, logs.String())) != 0 || !strings.Contains(logs.String(), "kill_switch") {
			t.Fatalf("status=%d hits=%d logs=%s", w.Code, hits.Load(), logs.String())
		}
	})
	t.Run("forward/airlock", func(t *testing.T) {
		t.Parallel()
		cfg := gitPushAuditConfig(false)
		cfg.SessionProfiling.Enabled = true
		cfg.Airlock.Enabled = true
		var hits atomic.Int32
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(backend.Close)
		p, logs, _ := policyAuditRig(t, cfg)
		installGitPushDialer(p, backend.Listener.Addr().String())
		sess := gitPushSession(t, p, cfg)
		sess.AirlockForScope(adaptiveScopeForHost(gitPushHost)).ForceSetTier(config.AirlockTierHard)
		w := serveGitPushForward(t, p, gitPushURL(gitPushPack), "0000", nil)
		if w.Code != http.StatusForbidden || hits.Load() != 0 || w.Header().Get(blockreason.HeaderReason) != string(blockreason.AirlockActive) {
			t.Fatalf("status=%d hits=%d reason=%q logs=%s", w.Code, hits.Load(), w.Header().Get(blockreason.HeaderReason), logs.String())
		}
		if len(gitPushAnomalyReasons(t, logs.String())) != 0 {
			t.Fatalf("earlier airlock observed the allowlist: %s", logs.String())
		}
	})
	t.Run("forward/contract", func(t *testing.T) {
		t.Parallel()
		cfg := gitPushAuditConfig(false)
		var hits atomic.Int32
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(backend.Close)
		p, logs, _ := policyAuditRig(t, cfg)
		p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, contractruntimetest.HTTPEnforceRule("r-other", "other.example.com", "/v1", http.MethodPost)))
		installGitPushDialer(p, backend.Listener.Addr().String())
		w := serveGitPushForward(t, p, gitPushURL(gitPushPack), "0000", http.Header{AgentHeader: []string{"agent-a"}})
		if w.Code != http.StatusForbidden || hits.Load() != 0 || w.Header().Get(blockreason.HeaderReason) != contractDefaultDenyReason {
			t.Fatalf("status=%d hits=%d reason=%q logs=%s", w.Code, hits.Load(), w.Header().Get(blockreason.HeaderReason), logs.String())
		}
		if len(gitPushAnomalyReasons(t, logs.String())) != 1 {
			t.Fatalf("logs=%s", logs.String())
		}
	})
	t.Run("forward/taint", func(t *testing.T) {
		t.Parallel()
		cfg := gitPushAuditConfig(false)
		cfg.SessionProfiling.Enabled = true
		var hits atomic.Int32
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		}))
		t.Cleanup(backend.Close)
		p, logs, _ := policyAuditRig(t, cfg)
		installGitPushDialer(p, backend.Listener.Addr().String())
		first := serveGitPushForward(t, p, gitPushURL(gitPushAllow), "0000", nil)
		second := serveGitPushForward(t, p, gitPushURL(gitPushPack), "0000", nil)
		if first.Code != http.StatusOK || second.Code != http.StatusForbidden || hits.Load() != 1 {
			t.Fatalf("first=%d second=%d hits=%d reason=%q logs=%s", first.Code, second.Code, hits.Load(), second.Header().Get(blockreason.HeaderReason), logs.String())
		}
		if second.Header().Get(blockreason.HeaderReason) != string(blockreason.AuthorityMismatch) || len(gitPushAnomalyReasons(t, logs.String())) != 1 {
			t.Fatalf("reason=%q logs=%s", second.Header().Get(blockreason.HeaderReason), logs.String())
		}
	})
	t.Run("intercept/body dlp", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		cfg := gitPushAuditConfig(false)
		p, logs, _ := policyAuditRig(t, cfg)
		w := serveGitPushIntercept(t, p, cfg, "https://"+gitPushHost+gitPushPack, "token="+credential, gitPushRoundTrip(&hits), nil)
		if w.Code != http.StatusForbidden || hits.Load() != 0 || w.Header().Get(blockreason.HeaderReason) != string(blockreason.DLPMatch) {
			t.Fatalf("status=%d hits=%d reason=%q logs=%s", w.Code, hits.Load(), w.Header().Get(blockreason.HeaderReason), logs.String())
		}
		if len(gitPushAnomalyReasons(t, logs.String())) != 1 {
			t.Fatalf("logs=%s", logs.String())
		}
	})
	t.Run("intercept/url credential", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		cfg := gitPushAuditConfig(false)
		p, logs, _ := policyAuditRig(t, cfg)
		w := serveGitPushIntercept(t, p, cfg, "https://"+gitPushHost+gitPushPack+"?token="+credential, "0000", gitPushRoundTrip(&hits), nil)
		if w.Code != http.StatusForbidden || hits.Load() != 0 || w.Header().Get(blockreason.HeaderReason) != string(blockreason.DLPMatch) || len(gitPushAnomalyReasons(t, logs.String())) != 0 {
			t.Fatalf("status=%d hits=%d reason=%q logs=%s", w.Code, hits.Load(), w.Header().Get(blockreason.HeaderReason), logs.String())
		}
	})
	t.Run("intercept/kill switch", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		cfg := gitPushAuditConfig(false)
		cfg.KillSwitch.Enabled = true
		p, logs, _ := policyAuditRig(t, cfg)
		w := serveGitPushIntercept(t, p, cfg, "https://"+gitPushHost+gitPushPack, "0000", gitPushRoundTrip(&hits), func(ic *InterceptContext) {
			ic.KillSwitch = p.ks
		})
		if w.Code == http.StatusOK || hits.Load() != 0 || len(gitPushAnomalyReasons(t, logs.String())) != 0 || !strings.Contains(logs.String(), "kill_switch") {
			t.Fatalf("status=%d hits=%d logs=%s", w.Code, hits.Load(), logs.String())
		}
	})
	t.Run("intercept/airlock", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		cfg := gitPushAuditConfig(false)
		cfg.SessionProfiling.Enabled = true
		cfg.Airlock.Enabled = true
		p, logs, _ := policyAuditRig(t, cfg)
		sess := gitPushSession(t, p, cfg)
		sess.AirlockForScope(adaptiveScopeForHost(gitPushHost)).ForceSetTier(config.AirlockTierHard)
		w := serveGitPushIntercept(t, p, cfg, "https://"+gitPushHost+gitPushPack, "0000", gitPushRoundTrip(&hits), func(ic *InterceptContext) {
			ic.Recorder = sess
		})
		if w.Code != http.StatusForbidden || hits.Load() != 0 || w.Header().Get(blockreason.HeaderReason) != string(blockreason.AirlockActive) {
			t.Fatalf("status=%d hits=%d reason=%q logs=%s", w.Code, hits.Load(), w.Header().Get(blockreason.HeaderReason), logs.String())
		}
		if len(gitPushAnomalyReasons(t, logs.String())) != 0 {
			t.Fatalf("logs=%s", logs.String())
		}
	})
	t.Run("intercept/contract", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		cfg := gitPushAuditConfig(false)
		p, logs, _ := policyAuditRig(t, cfg)
		p.contractLoaderPtr.Store(testContractLoader(t, contractruntime.ModeLive, contractruntimetest.HTTPEnforceRule("r-other", "other.example.com", "/v1", http.MethodPost)))
		w := serveGitPushIntercept(t, p, cfg, "https://"+gitPushHost+gitPushPack, "0000", gitPushRoundTrip(&hits), func(ic *InterceptContext) {
			ic.Agent = "agent-a"
		})
		if w.Code != http.StatusForbidden || hits.Load() != 0 || w.Header().Get(blockreason.HeaderReason) != contractDefaultDenyReason {
			t.Fatalf("status=%d hits=%d reason=%q logs=%s", w.Code, hits.Load(), w.Header().Get(blockreason.HeaderReason), logs.String())
		}
		if len(gitPushAnomalyReasons(t, logs.String())) != 1 {
			t.Fatalf("logs=%s", logs.String())
		}
	})
	t.Run("redirect/request policy", func(t *testing.T) {
		t.Parallel()
		got := runGitPushRedirect(t, false, true)
		if got.status != http.StatusForbidden || got.initial != 1 || got.final != 0 || got.reason != string(blockreason.RequestPolicyDeny) {
			t.Fatalf("status=%d initial=%d final=%d reason=%q logs=%s", got.status, got.initial, got.final, got.reason, got.logs)
		}
		if len(gitPushAnomalyReasons(t, got.logs)) != 1 {
			t.Fatalf("logs=%s", got.logs)
		}
	})
}

func TestGitPushAuditModeDefaults(t *testing.T) {
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
	markedURL, err := url.Parse("https://" + gitPushHost + gitPushPack)
	if err != nil {
		t.Fatal(err)
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
			cfg := gitPushAuditConfig(!tc.audit)
			cfg.Enforce = parsed.Enforce
			p, logs, _ := policyAuditRig(t, cfg)
			decision := evaluateGitPushAllowlist(cfg.GitProtection, http.MethodPost, markedURL)
			block, observed := p.refuseGitPushAllowlist(cfg, p.logger, audit.LogContext{}, decision, decision.Reason)
			if tc.audit {
				if block || !observed || len(gitPushAnomalyReasons(t, logs.String())) != 1 {
					t.Fatalf("block=%v observed=%v logs=%s", block, observed, logs.String())
				}
				return
			}
			if !block || observed || len(gitPushAnomalyReasons(t, logs.String())) != 0 {
				t.Fatalf("block=%v observed=%v logs=%s", block, observed, logs.String())
			}
		})
	}
}

func TestGitPushAuditModeReload(t *testing.T) {
	t.Parallel()
	admitted := gitPushAuditConfig(false)
	p, logs, _ := policyAuditRig(t, admitted)
	var hits atomic.Int32
	rt := gitPushRoundTrip(&hits)
	ic := &InterceptContext{
		TargetHost: gitPushHost, TargetPort: "443", Config: admitted, Scanner: p.scannerPtr.Load(),
		Logger: p.logger, Metrics: p.metrics, Proxy: p, RequestID: "git-push-reload", ClientIP: "192.0.2.1",
	}
	handler := newInterceptHandler(ic, rt)
	req := func() *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+gitPushHost+gitPushPack, strings.NewReader("0000"))
		r.Host = gitPushHost + ":443"
		return r
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req())
	if w.Code != http.StatusOK || hits.Load() != 1 || len(gitPushAnomalyReasons(t, logs.String())) != 1 {
		t.Fatalf("admitted audit status=%d hits=%d logs=%s", w.Code, hits.Load(), logs.String())
	}
	attackFlipEnforce(t, p, true)
	w = httptest.NewRecorder()
	before := hits.Load()
	handler.ServeHTTP(w, req())
	if w.Code != http.StatusForbidden || hits.Load() != before || w.Header().Get(blockreason.HeaderReason) != string(blockreason.RequestPolicyDeny) {
		t.Fatalf("reloaded enforce status=%d hits=%d reason=%q logs=%s", w.Code, hits.Load(), w.Header().Get(blockreason.HeaderReason), logs.String())
	}

	enforced := gitPushAuditConfig(true)
	p2, logs2, _ := policyAuditRig(t, enforced)
	var hits2 atomic.Int32
	ic2 := &InterceptContext{
		TargetHost: gitPushHost, TargetPort: "443", Config: enforced, Scanner: p2.scannerPtr.Load(),
		Logger: p2.logger, Metrics: p2.metrics, Proxy: p2, RequestID: "git-push-reload-on", ClientIP: "192.0.2.1",
	}
	handler2 := newInterceptHandler(ic2, gitPushRoundTrip(&hits2))
	attackFlipEnforce(t, p2, false)
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+gitPushHost+gitPushPack, strings.NewReader("0000"))
	r2.Host = gitPushHost + ":443"
	handler2.ServeHTTP(w2, r2)
	if w2.Code != http.StatusForbidden || hits2.Load() != 0 {
		t.Fatalf("admitted enforce followed live audit status=%d hits=%d logs=%s", w2.Code, hits2.Load(), logs2.String())
	}

	same := gitPushAuditConfig(false)
	p3, _, _ := policyAuditRig(t, same)
	attackReload(t, p3, gitPushAuditConfig(false))
	decision := evaluateGitPushAllowlist(same.GitProtection, http.MethodPost, mustGitPushURL(t))
	block, observed := p3.refuseGitPushAllowlist(same, p3.logger, audit.LogContext{}, decision, decision.Reason)
	if block || !observed {
		t.Fatalf("reload without change block=%v observed=%v", block, observed)
	}
}

func mustGitPushURL(t *testing.T) *url.URL {
	t.Helper()
	parsed, err := url.Parse("https://" + gitPushHost + gitPushPack)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestGitPushAuditModeCleanCredit(t *testing.T) {
	t.Parallel()
	t.Run("intercept", func(t *testing.T) {
		t.Parallel()
		cfg := gitPushAuditConfig(false)
		cfg.AdaptiveEnforcement.Enabled = true
		cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0.1
		p, _, _ := policyAuditRig(t, cfg)
		var allowHits atomic.Int32
		allowRec := &interceptMockRecorder{}
		w := serveGitPushIntercept(t, p, cfg, "https://"+gitPushHost+gitPushAllow, "0000", gitPushRoundTrip(&allowHits), func(ic *InterceptContext) {
			ic.Recorder = allowRec
		})
		if w.Code != http.StatusOK || allowHits.Load() != 1 || !allowRec.cleanCalled {
			t.Fatalf("allowlisted status=%d hits=%d clean=%v", w.Code, allowHits.Load(), allowRec.cleanCalled)
		}
		var denyHits atomic.Int32
		denyRec := &interceptMockRecorder{}
		w = serveGitPushIntercept(t, p, cfg, "https://"+gitPushHost+gitPushPack, "0000", gitPushRoundTrip(&denyHits), func(ic *InterceptContext) {
			ic.Recorder = denyRec
		})
		if w.Code != http.StatusOK || denyHits.Load() != 1 || denyRec.cleanCalled {
			t.Fatalf("observed status=%d hits=%d clean=%v", w.Code, denyHits.Load(), denyRec.cleanCalled)
		}
	})
	t.Run("forward", func(t *testing.T) {
		t.Parallel()
		cfg := gitPushAuditConfig(false)
		cfg.SessionProfiling.Enabled = true
		cfg.AdaptiveEnforcement.Enabled = true
		cfg.AdaptiveEnforcement.DecayPerCleanRequest = 1
		// The allowlisted response is an untrusted external exposure, so a later
		// push is a taint publish ask. That floor is covered separately.
		cfg.Taint.Enabled = false
		var hits atomic.Int32
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		}))
		t.Cleanup(backend.Close)
		p, logs, _ := policyAuditRig(t, cfg)
		installGitPushDialer(p, backend.Listener.Addr().String())
		sess := gitPushSession(t, p, cfg)
		sess.threatScore = 4
		w := serveGitPushForward(t, p, gitPushURL(gitPushAllow), "0000", nil)
		if w.Code != http.StatusOK || hits.Load() != 1 || sess.ThreatScore() != 3 {
			t.Fatalf("allowlisted status=%d hits=%d score=%v reason=%q body=%s logs=%s", w.Code, hits.Load(), sess.ThreatScore(), w.Header().Get(blockreason.HeaderReason), w.Body.String(), logs.String())
		}
		sess.threatScore = 4
		w = serveGitPushForward(t, p, gitPushURL(gitPushPack), "0000", nil)
		if w.Code != http.StatusOK || hits.Load() != 2 || sess.ThreatScore() != 4 {
			t.Fatalf("observed status=%d hits=%d score=%v reason=%q body=%s logs=%s", w.Code, hits.Load(), sess.ThreatScore(), w.Header().Get(blockreason.HeaderReason), w.Body.String(), logs.String())
		}
	})
}

func TestGitPushAuditModeAllowlistedAndNotAPush(t *testing.T) {
	t.Parallel()
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("allowlisted/enforce=%t", enforce), func(t *testing.T) {
			t.Parallel()
			got := runGitPushForward(t, enforce, gitPushURL(gitPushAllow), "0000")
			if got.status != http.StatusOK || got.upstream != 1 || got.reason != "" || len(gitPushAnomalyReasons(t, got.logs)) != 0 || gitPushActionCount(t, got.metrics) != 0 {
				t.Fatalf("status=%d upstream=%d reason=%q logs=%s", got.status, got.upstream, got.reason, got.logs)
			}
		})
	}
}
