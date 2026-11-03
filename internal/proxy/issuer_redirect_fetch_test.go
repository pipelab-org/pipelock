// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// fetchRedirectHop builds the request net/http hands CheckRedirect for a hop:
// the target URL, the redirect response that produced it, and the chain so far.
func fetchRedirectHop(t *testing.T, cfg *config.Config, sc *scanner.Scanner, transport string, status int, target string, locations ...string) (*http.Request, []*http.Request) {
	t.Helper()
	ctx := context.WithValue(t.Context(), ctxKeyClientIP, "127.0.0.1")
	ctx = context.WithValue(ctx, ctxKeyRequestID, "req-delegation")
	ctx = context.WithValue(ctx, ctxKeyAgent, agentAnonymous)
	ctx = context.WithValue(ctx, ctxKeyAgentConfig, cfg)
	ctx = context.WithValue(ctx, ctxKeyAgentScanner, sc)
	if transport != "" {
		ctx = context.WithValue(ctx, ctxKeyRedirectTransport, transport)
	}
	source := httptest.NewRequestWithContext(ctx, http.MethodGet, delegationSourceURL(), nil)
	header := http.Header{}
	for _, l := range locations {
		header.Add("Location", l)
	}
	hop := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	hop.Response = &http.Response{StatusCode: status, Header: header, Request: source}
	return hop, []*http.Request{source}
}

func delegationFetchProxy(t *testing.T, mutate func(*config.Config)) (*Proxy, *config.Config, *scanner.Scanner) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.IssuedRedirectDelegations = []config.IssuedRedirectDelegation{delegationFixture()}
	if mutate != nil {
		mutate(cfg)
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p, cfg, sc
}

func TestFetchRedirectIssuedDelegation(t *testing.T) {
	good := delegationFilesURL(delegationFilesPath, delegationTicketQuery())

	t.Run("baseline: the hop is blocked without a delegation", func(t *testing.T) {
		p, cfg, sc := delegationFetchProxy(t, func(c *config.Config) { c.FetchProxy.Monitoring.IssuedRedirectDelegations = nil })
		hop, via := fetchRedirectHop(t, cfg, sc, "", http.StatusFound, good, good)
		if err := p.client.CheckRedirect(hop, via); err == nil {
			t.Fatal("entropy hop allowed without a delegation")
		}
	})

	t.Run("the exact Location that the source issued is followed", func(t *testing.T) {
		p, cfg, sc := delegationFetchProxy(t, nil)
		hop, via := fetchRedirectHop(t, cfg, sc, "", http.StatusFound, good, good)
		if err := p.client.CheckRedirect(hop, via); err != nil {
			t.Fatalf("delegated hop blocked: %v", err)
		}
	})

	t.Run("reordered query follows; a changed one does not", func(t *testing.T) {
		p, cfg, sc := delegationFetchProxy(t, nil)
		hop, via := fetchRedirectHop(t, cfg, sc, "", http.StatusFound, delegationFilesURL(delegationFilesPath, "ApiVersion=2.0&tempauth="+issuedTestToken()), good)
		if err := p.client.CheckRedirect(hop, via); err != nil {
			t.Fatalf("reordered hop blocked: %v", err)
		}
		hop, via = fetchRedirectHop(t, cfg, sc, "", http.StatusFound, delegationFilesURL(delegationFilesPath, "tempauth="+issuedTestToken()+"Z&ApiVersion=2.0"), good)
		if err := p.client.CheckRedirect(hop, via); err == nil {
			t.Fatal("a hop that is not the issued Location was allowed")
		}
	})

	for _, tc := range []struct {
		name      string
		mutate    func(*config.Config)
		status    int
		target    string
		locations []string
		transport string
		noSource  bool
	}{
		{
			name: "source on another path", target: good, status: http.StatusFound, locations: []string{good},
			mutate: func(c *config.Config) {
				c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].Source.PathPrefixes = []string{"/v2/"}
			},
		},
		{
			name: "target origin not listed", target: good, status: http.StatusFound, locations: []string{good},
			mutate: func(c *config.Config) {
				c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins = []string{"https://other.vendor.example"}
			},
		},
		{
			name: "expired", target: good, status: http.StatusFound, locations: []string{good},
			mutate: func(c *config.Config) { c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].Expires = "2000-01-01" },
		},
		{name: "not a redirect status", target: good, status: http.StatusOK, locations: []string{good}},
		{name: "two Location values", target: good, status: http.StatusFound, locations: []string{good, good}},
		{name: "no Location", target: good, status: http.StatusFound},
		{name: "forward transport returns redirects to the client", target: good, status: http.StatusFound, locations: []string{good}, transport: TransportForward},
		{
			name: "credential in a value", status: http.StatusFound, transport: "",
			target:    delegationFilesURL(delegationFilesPath, delegationTicketQuery()+"&k="+issuerUnissuedSecret()),
			locations: []string{delegationFilesURL(delegationFilesPath, delegationTicketQuery()+"&k="+issuerUnissuedSecret())},
		},
		{
			name: "high-entropy query key", status: http.StatusFound,
			target:    delegationFilesURL(delegationFilesPath, issuedTestToken()+"=1"),
			locations: []string{delegationFilesURL(delegationFilesPath, issuedTestToken()+"=1")},
		},
		{name: "no response proof", target: good, status: http.StatusFound, noSource: true},
	} {
		t.Run("no relief: "+tc.name, func(t *testing.T) {
			p, cfg, sc := delegationFetchProxy(t, tc.mutate)
			hop, via := fetchRedirectHop(t, cfg, sc, tc.transport, tc.status, tc.target, tc.locations...)
			if tc.noSource {
				hop.Response = nil
			}
			if err := p.client.CheckRedirect(hop, via); err == nil {
				t.Fatal("hop allowed")
			}
		})
	}

	t.Run("live policy that dropped the delegation withdraws it", func(t *testing.T) {
		p, cfg, sc := delegationFetchProxy(t, nil)
		live := cfg.Clone()
		live.FetchProxy.Monitoring.IssuedRedirectDelegations = nil
		p.cfgPtr.Store(live)
		hop, via := fetchRedirectHop(t, cfg, sc, "", http.StatusFound, good, good)
		if err := p.client.CheckRedirect(hop, via); err == nil {
			t.Fatal("hop allowed after the live policy dropped the delegation")
		}
	})
}

func TestFetchRedirectIssuedDelegationIsRecordedInAudit(t *testing.T) {
	good := delegationFilesURL(delegationFilesPath, delegationTicketQuery())
	p, cfg, sc := delegationFetchProxy(t, func(c *config.Config) { c.FlightRecorder.RequireReceipts = true })
	// No emitter is wired, so the allowance cannot be durably recorded and the
	// hop fails closed instead of being followed.
	hop, via := fetchRedirectHop(t, cfg, sc, "", http.StatusFound, good, good)
	err := p.client.CheckRedirect(hop, via)
	if err == nil {
		t.Fatal("hop followed although its allowance could not be recorded")
	}
	if blocked, ok := blockedRequestErrorFrom(err); !ok || blocked.layer != blockLayerIssuerAllowReceipt {
		t.Fatalf("error = %v, want the issuer allow receipt block", err)
	}
	if strings.Contains(err.Error(), issuedTestToken()) {
		t.Fatal("the error carries the signed value")
	}
}
