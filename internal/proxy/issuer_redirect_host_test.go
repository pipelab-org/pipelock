// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// heuristicEntropyHost returns a host whose subdomain label trips the
// heuristic subdomain entropy finding (not a structural one) under cfg's
// scanner. Probing the scanner keeps the fixture honest if thresholds move.
func heuristicEntropyHost(t *testing.T, sc *scanner.Scanner) string {
	t.Helper()
	for _, label := range []string{
		"aB3xK9mZ2wQ7rL5yN8vC4jF6", "xK9mZ2wQ7rL5yN8vC4jF6hD1", "q7Zr5Lm2Xw9Kb3Vn8Cj4Fy6H", "mZ2wQ7rL5yN8vC4jF6hD1eG0",
	} {
		host := strings.ToLower(label) + ".vendor.example"
		res := sc.Scan(t.Context(), "https://"+host+"/")
		if !res.Allowed && res.Scanner == scanner.ScannerSubdomainEntropy && res.IsEntropyOnly() {
			return host
		}
	}
	t.Fatal("no fixture label trips the heuristic subdomain finding")
	return ""
}

func TestIssuedRedirectHostRelief(t *testing.T) {
	t.Run("intercepted: a listed high-entropy host is followed only at the issued URL", func(t *testing.T) {
		var host string
		e := newDelegationEnv(t, func(c *config.Config) {
			probe := scanner.MustNew(c)
			t.Cleanup(probe.Close)
			host = heuristicEntropyHost(t, probe)
			c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins = []string{"https://" + host}
		})
		issued := "https://" + host + "/dl/archive.bin?id=7"
		if got := e.do("agent-one", http.MethodGet, issued); got != http.StatusForbidden {
			t.Fatalf("premise: unissued status = %d, want 403 from subdomain entropy", got)
		}
		e.issue(http.StatusFound, issued)
		if got := e.issueAndFollow(issued); got != http.StatusOK {
			t.Fatalf("issued URL status = %d, want 200", got)
		}
		// The same host is not open: another path, another query, another
		// session still meet the finding.
		for name, url := range map[string]string{
			"another path":  "https://" + host + "/dl/other.bin?id=7",
			"another query": "https://" + host + "/dl/archive.bin?id=8",
		} {
			if got := e.do("agent-one", http.MethodGet, url); got != http.StatusForbidden {
				t.Errorf("%s: status = %d, want 403", name, got)
			}
		}
		if got := e.do("agent-two", http.MethodGet, issued); got != http.StatusForbidden {
			t.Errorf("another session: status = %d, want 403", got)
		}
	})

	t.Run("a structural exfiltration label is never relieved", func(t *testing.T) {
		host := strings.Repeat("a1b2c3d4", 6) + ".vendor.example"
		e := newDelegationEnv(t, func(c *config.Config) {
			c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins = []string{"https://" + host}
		})
		res := e.sc.Scan(t.Context(), "https://"+host+"/")
		if res.Allowed || res.Scanner != scanner.ScannerSubdomainEntropy || res.IsEntropyOnly() {
			t.Fatalf("premise: %+v is not a structural subdomain finding", res)
		}
		issued := "https://" + host + "/dl/archive.bin?id=7"
		e.issue(http.StatusFound, issued)
		if got := e.issueAndFollow(issued); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})
}

func connectDelegationProxy(t *testing.T, mutate func(*config.Config)) (*Proxy, *config.Config, *scanner.Scanner) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.TLSInterception.Enabled = true
	cfg.FetchProxy.Monitoring.IssuedRedirectDelegations = []config.IssuedRedirectDelegation{delegationFixture()}
	if mutate != nil {
		mutate(cfg)
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	host := heuristicEntropyHost(t, sc)
	cfg.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins = []string{"https://" + host}
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p, cfg, sc
}

func TestConnectIssuedHostContext(t *testing.T) {
	const (
		agent    = "agent-one"
		clientIP = "10.0.0.1"
	)
	auth := envelope.ActorAuthBound
	seed := func(t *testing.T, p *Proxy, cfg *config.Config, session string) (host string) {
		t.Helper()
		host = strings.TrimPrefix(cfg.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins[0], "https://")
		d := compileIssuedRedirectDelegations(cfg, time.Now())
		target := mustIssuerQueryURL(t, "https://"+host+"/dl/archive.bin?id=7")
		p.issuerCookieRuntime.Load().query.rememberIssuedLocation(session, target, d[0].scope, time.Now())
		return host
	}
	session := func(cfg *config.Config) string { return sessionKeyFor(cfg, agent, clientIP, auth) }

	t.Run("issued host, intercepted tunnel, same session", func(t *testing.T) {
		p, cfg, sc := connectDelegationProxy(t, nil)
		host := seed(t, p, cfg, session(cfg))
		synthetic := "https://" + host + ":443/"
		if res := sc.Scan(t.Context(), synthetic); res.Allowed {
			t.Fatal("premise: the tunnel host is not blocked")
		}
		ctx, used, ok := p.connectIssuedHostContext(t.Context(), cfg, host, "443", agent, clientIP, auth)
		if !ok {
			t.Fatal("no relief for an issued host")
		}
		if res := sc.Scan(ctx, synthetic); !res.Allowed || !used.Load() {
			t.Fatalf("scan = %+v used=%t, want allowed with relief consumed", res, used.Load())
		}
		// The relief names this host only: a second entropic host stays blocked.
		other := "https://q7zr5lm2xw9kb3vn8cj4fy6h.vendor.example:443/"
		if base := sc.Scan(t.Context(), other); base.Allowed || base.Scanner != scanner.ScannerSubdomainEntropy {
			t.Fatalf("premise: second host baseline = %+v", base)
		}
		if res := sc.Scan(ctx, other); res.Allowed {
			t.Fatal("relief reached another host")
		}
	})

	for name, tc := range map[string]struct {
		mutate func(*config.Config)
		call   func(p *Proxy, cfg *config.Config, host string) bool
	}{
		"another session": {call: func(p *Proxy, cfg *config.Config, host string) bool {
			_, _, ok := p.connectIssuedHostContext(t.Context(), cfg, host, "443", "agent-two", clientIP, auth)
			return ok
		}},
		"self-declared identity": {call: func(p *Proxy, cfg *config.Config, host string) bool {
			_, _, ok := p.connectIssuedHostContext(t.Context(), cfg, host, "443", agent, clientIP, envelope.ActorAuthSelfDeclared)
			return ok
		}},
		"other port": {call: func(p *Proxy, cfg *config.Config, host string) bool {
			_, _, ok := p.connectIssuedHostContext(t.Context(), cfg, host, "8443", agent, clientIP, auth)
			return ok
		}},
		"other host": {call: func(p *Proxy, cfg *config.Config, host string) bool {
			_, _, ok := p.connectIssuedHostContext(t.Context(), cfg, "other."+host, "443", agent, clientIP, auth)
			return ok
		}},
		"passthrough in the snapshot": {call: func(p *Proxy, cfg *config.Config, host string) bool {
			c := cfg.Clone()
			c.TLSInterception.PassthroughDomains = []string{host}
			_, _, ok := p.connectIssuedHostContext(t.Context(), c, host, "443", agent, clientIP, auth)
			return ok
		}},
		"passthrough in the live policy": {call: func(p *Proxy, cfg *config.Config, host string) bool {
			live := cfg.Clone()
			live.TLSInterception.PassthroughDomains = []string{"*." + strings.SplitN(host, ".", 2)[1]}
			p.cfgPtr.Store(live)
			_, _, ok := p.connectIssuedHostContext(t.Context(), cfg, host, "443", agent, clientIP, auth)
			return ok
		}},
		"interception off in the live policy": {call: func(p *Proxy, cfg *config.Config, host string) bool {
			live := cfg.Clone()
			live.TLSInterception.Enabled = false
			p.cfgPtr.Store(live)
			_, _, ok := p.connectIssuedHostContext(t.Context(), cfg, host, "443", agent, clientIP, auth)
			return ok
		}},
		"interception off in the snapshot": {call: func(p *Proxy, cfg *config.Config, host string) bool {
			c := cfg.Clone()
			c.TLSInterception.Enabled = false
			_, _, ok := p.connectIssuedHostContext(t.Context(), c, host, "443", agent, clientIP, auth)
			return ok
		}},
		"delegation withdrawn": {call: func(p *Proxy, cfg *config.Config, host string) bool {
			live := cfg.Clone()
			live.FetchProxy.Monitoring.IssuedRedirectDelegations = nil
			p.cfgPtr.Store(live)
			_, _, ok := p.connectIssuedHostContext(t.Context(), cfg, host, "443", agent, clientIP, auth)
			return ok
		}},
		"delegation expired": {call: func(p *Proxy, cfg *config.Config, host string) bool {
			c := cfg.Clone()
			c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].Expires = "2000-01-01"
			p.cfgPtr.Store(c)
			_, _, ok := p.connectIssuedHostContext(t.Context(), c, host, "443", agent, clientIP, auth)
			return ok
		}},
		"no delegations": {call: func(p *Proxy, cfg *config.Config, host string) bool {
			_, _, ok := p.connectIssuedHostContext(t.Context(), config.Defaults(), host, "443", agent, clientIP, auth)
			return ok
		}},
		"nil proxy": {call: func(_ *Proxy, cfg *config.Config, host string) bool {
			var p *Proxy
			_, _, ok := p.connectIssuedHostContext(t.Context(), cfg, host, "443", agent, clientIP, auth)
			return ok
		}},
	} {
		t.Run("no relief: "+name, func(t *testing.T) {
			p, cfg, _ := connectDelegationProxy(t, tc.mutate)
			host := seed(t, p, cfg, session(cfg))
			if tc.call(p, cfg, host) {
				t.Fatal("relief granted")
			}
		})
	}

	t.Run("no relief without any redirect delivered", func(t *testing.T) {
		p, cfg, _ := connectDelegationProxy(t, nil)
		host := strings.TrimPrefix(cfg.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins[0], "https://")
		if _, _, ok := p.connectIssuedHostContext(t.Context(), cfg, host, "443", agent, clientIP, auth); ok {
			t.Fatal("relief for a host nothing issued")
		}
	})
}

func TestFetchRedirectIssuedDelegationHostRelief(t *testing.T) {
	var host string
	p, cfg, sc := delegationFetchProxy(t, func(c *config.Config) {
		probe := scanner.MustNew(c)
		t.Cleanup(probe.Close)
		host = heuristicEntropyHost(t, probe)
		c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins = []string{"https://" + host}
	})
	issued := "https://" + host + "/dl/archive.bin?id=7"
	hop, via := fetchRedirectHop(t, cfg, sc, "", http.StatusFound, issued, issued)
	if err := p.client.CheckRedirect(hop, via); err != nil {
		t.Fatalf("issued high-entropy host blocked: %v", err)
	}
	// The same host with a different path was not issued.
	hop, via = fetchRedirectHop(t, cfg, sc, "", http.StatusFound, "https://"+host+"/dl/other.bin?id=7", issued)
	if err := p.client.CheckRedirect(hop, via); err == nil {
		t.Fatal("a URL that is not the issued Location was followed")
	}
}
