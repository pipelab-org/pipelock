// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestIssuerIDHistorySurvivesQueryEviction(t *testing.T) {
	s := newTestServerIDStore(t)
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	now := time.Now()
	s.recordSent("owner", origin, nil, []byte(agentBlob), true, now)
	s.mintServerID("owner", origin, serverIDListed, now)
	s.remember("owner", origin, "page", "retained", now)
	for i := 0; i < issuerCookieMaxSessions; i++ {
		s.remember(fmt.Sprintf("query-%d", i), origin, "page", "other", now.Add(time.Duration(i+1)*time.Second))
	}
	if _, exists := s.used["owner"]; exists {
		t.Fatal("positive control: query owner was not evicted")
	}
	if !s.serverIDIssued("owner", origin, serverIDListed) {
		t.Fatal("query eviction revoked ID evidence")
	}
	s.mintServerID("owner", origin, agentBlob, now)
	if s.serverIDIssued("owner", origin, agentBlob) {
		t.Fatal("query eviction forgot sent history")
	}
}

func TestIssuerIDIdentityReload(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	p, cfg := newSentIssuerProxy(t)
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	key := sessionKeyFor(cfg, "owner", "192.0.2.1", envelope.ActorAuthBound)
	peer := sessionKeyFor(cfg, "peer", "192.0.2.1", envelope.ActorAuthBound)
	original := p.issuerCookieRuntime.Load().query
	original.recordSent(key, origin, nil, nil, true, time.Now())
	original.recordSent(peer, origin, nil, nil, true, time.Now())
	original.mintServerID(key, origin, serverIDListed, time.Now())
	original.mintServerID(peer, origin, serverIDListed, time.Now())
	original.taintSentLocked(key)
	for _, state := range []struct {
		name string
		bind bool
	}{
		{"", false}, {"default-owner", false}, {"default-owner", true}, {"default-owner", false}, {"", false},
	} {
		next := cfg.Clone()
		next.DefaultAgentIdentity, next.BindDefaultAgentIdentity = state.name, state.bind
		old := &InterceptContext{Proxy: p, Config: cfg, Agent: "peer", ClientIP: "192.0.2.1", ActorAuth: envelope.ActorAuthBound, IssuerRuntime: p.issuerCookieRuntime.Load()}
		if !p.Reload(next, scanner.MustNew(next)) {
			t.Fatal("enabled reload failed")
		}
		if old.issuerServerIDStore() != nil {
			t.Fatal("stale tunnel retained evidence access")
		}
		live := p.issuerCookieRuntime.Load().query
		if live != original {
			t.Fatal("enabled identity reload erased history")
		}
		live.mintServerID(key, origin, serverIDListed, time.Now())
		if live.serverIDIssued(key, origin, serverIDListed) {
			t.Fatal("identity reload revived own tainted IDs")
		}
		if !live.serverIDIssued(peer, origin, serverIDListed) {
			t.Fatal("identity reload revoked bound peer")
		}
		for _, auth := range []envelope.ActorAuth{envelope.ActorAuthUnknown, envelope.ActorAuthSelfDeclared, envelope.ActorAuthMatched} {
			ic := &InterceptContext{Proxy: p, Config: next, Agent: "peer", ClientIP: "192.0.2.1", ActorAuth: auth}
			if ic.issuerServerIDStore() != nil {
				t.Fatal("reload promoted untrusted raw grade")
			}
		}
		cfg = next
	}
	off := cfg.Clone()
	off.RequestBodyScanning.ScanHeaders = false
	if !p.Reload(off, scanner.MustNew(off)) {
		t.Fatal("disable reload failed")
	}
	if (&InterceptContext{Proxy: p, Config: off, ActorAuth: envelope.ActorAuthBound}).issuerServerIDStore() != nil {
		t.Fatal("disabled prerequisite retained ID access")
	}
	on := cfg.Clone()
	if !p.Reload(on, scanner.MustNew(on)) {
		t.Fatal("re-enable reload failed")
	}
	fresh := p.issuerCookieRuntime.Load().query
	if fresh == original || fresh.serverIDIssued(peer, origin, serverIDListed) {
		t.Fatal("disabled evidence revived")
	}
	fresh.recordSent(key, origin, nil, nil, true, time.Now())
	fresh.mintServerID(key, origin, serverIDListed, time.Now())
	if !fresh.serverIDIssued(key, origin, serverIDListed) {
		t.Fatal("explicit reset retained taint")
	}
}

func TestIssuerIDConcurrentCallerIsolation(t *testing.T) {
	p, cfg := newSentIssuerProxy(t)
	cfg.DefaultAgentIdentity = "owner"
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	store := p.issuerCookieRuntime.Load().query
	key := sessionKeyFor(cfg, "owner", "192.0.2.1", envelope.ActorAuthConfigDefault)
	store.recordSent(key, origin, nil, nil, true, time.Now())
	store.mintServerID(key, origin, serverIDListed, time.Now())
	var wg sync.WaitGroup
	for _, auth := range []envelope.ActorAuth{envelope.ActorAuthUnknown, envelope.ActorAuthSelfDeclared, envelope.ActorAuthMatched} {
		wg.Go(func() {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, origin.String(), strings.NewReader(agentBlob))
			for range 32 {
				p.recordIssuerForwardSent(cfg, "owner", "192.0.2.1", auth, req, nil)
				p.taintIssuerSessionForStream(cfg, "owner", "192.0.2.1", auth, origin)
			}
		})
	}
	wg.Go(func() {
		for range 32 {
			store.mintServerID(key, origin, serverIDOther, time.Now())
		}
	})
	wg.Wait()
	if !store.serverIDIssued(key, origin, serverIDListed) || !store.serverIDIssued(key, origin, serverIDOther) {
		t.Fatal("concurrent untrusted traffic poisoned trusted caller")
	}
}
