// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func benchDelegationProxy(b *testing.B, delegated bool) (*Proxy, *config.Config) {
	b.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	if delegated {
		cfg.FetchProxy.Monitoring.IssuedRedirectDelegations = []config.IssuedRedirectDelegation{delegationFixture()}
	}
	sc := scanner.MustNew(cfg)
	b.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(p.Close)
	return p, cfg
}

// The disabled path is what every intercepted response and every
// entropy-blocked request pays when no delegation is configured.
func BenchmarkIssuedRedirectDisabled(b *testing.B) {
	p, cfg := benchDelegationProxy(b, false)
	store := newIssuerQueryStore()
	ic := &InterceptContext{Proxy: p, Config: cfg}
	target := mustIssuerQueryURL(&testing.T{}, delegationFilesURL(delegationFilesPath, delegationTicketQuery()))
	source := httptest.NewRequestWithContext(context.Background(), http.MethodGet, delegationSourceURL(), nil)
	resp := &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {target.String()}}, Request: source}
	b.ReportAllocs()
	for b.Loop() {
		ic.recordIssuedLocation(store, "session", resp)
		_ = ic.issuedLocationAllowed(store, "session", target)
	}
}

// Mint pays for compiling the active delegations and one HMAC per match.
func BenchmarkIssuedRedirectMint(b *testing.B) {
	p, cfg := benchDelegationProxy(b, true)
	store := newIssuerQueryStore()
	ic := &InterceptContext{Proxy: p, Config: cfg}
	target := mustIssuerQueryURL(&testing.T{}, delegationFilesURL(delegationFilesPath, delegationTicketQuery()))
	source := httptest.NewRequestWithContext(context.Background(), http.MethodGet, delegationSourceURL(), nil)
	resp := &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {target.String()}}, Request: source}
	b.ReportAllocs()
	for b.Loop() {
		ic.recordIssuedLocation(store, "session", resp)
	}
}

// Lookup is paid only by a request the entropy gate already blocked.
func BenchmarkIssuedRedirectLookup(b *testing.B) {
	for _, entries := range []int{1, issuerCookieMaxEntries} {
		b.Run(fmt.Sprintf("entries=%d", entries), func(b *testing.B) {
			p, cfg := benchDelegationProxy(b, true)
			store := newIssuerQueryStore()
			ic := &InterceptContext{Proxy: p, Config: cfg}
			scope := ic.Proxy.issuedRedirects(cfg, time.Now())[0].scope
			for i := 0; i < entries-1; i++ {
				store.rememberIssuedLocation("session", mustIssuerQueryURL(&testing.T{}, fmt.Sprintf("https://files.vendor.example/d/%d?k=v", i)), scope, time.Now())
			}
			target := mustIssuerQueryURL(&testing.T{}, delegationFilesURL(delegationFilesPath, delegationTicketQuery()))
			store.rememberIssuedLocation("session", target, scope, time.Now())
			b.ReportAllocs()
			for b.Loop() {
				if !ic.issuedLocationAllowed(store, "session", target) {
					b.Fatal("evidence not found")
				}
			}
		})
	}
}

// A miss scans every entry; it is the worst case for a full session.
func BenchmarkIssuedRedirectLookupMiss(b *testing.B) {
	p, cfg := benchDelegationProxy(b, true)
	store := newIssuerQueryStore()
	ic := &InterceptContext{Proxy: p, Config: cfg}
	scope := ic.Proxy.issuedRedirects(cfg, time.Now())[0].scope
	for i := 0; i < issuerCookieMaxEntries; i++ {
		store.rememberIssuedLocation("session", mustIssuerQueryURL(&testing.T{}, fmt.Sprintf("https://files.vendor.example/d/%d?k=v", i)), scope, time.Now())
	}
	target := mustIssuerQueryURL(&testing.T{}, delegationFilesURL(delegationFilesPath, delegationTicketQuery()))
	b.ReportAllocs()
	for b.Loop() {
		if ic.issuedLocationAllowed(store, "session", target) {
			b.Fatal("unexpected evidence")
		}
	}
}
