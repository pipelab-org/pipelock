// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestIssuerIDFreezeKeepsKnownIDs(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://graph.vendor.example/items")
	other := mustIssuerQueryURL(t, "https://api.llm.vendor.example/items")
	for _, cause := range []string{"unread", "request", "destination", "total", "stream"} {
		t.Run(cause, func(t *testing.T) {
			s := newTestServerIDStore(t)
			now := time.Now()
			s.recordSent("reader", origin, nil, nil, true, now)
			s.mintServerID("reader", origin, serverIDListed, now)
			s.recordSent("reader", other, nil, nil, true, now)
			bucket := s.idDestinationLocked("reader", origin)
			switch cause {
			case "unread":
				s.recordSent("reader", origin, nil, nil, false, now)
			case "request":
				s.recordSent("reader", origin, nil, []byte(strings.Repeat(agentBlob+" ", issuerSentMaxTokensPerRequest+1)), true, now)
			case "destination":
				for i := range issuerSentMaxEntries {
					bucket.sent[s.digestFields("fixture", fmt.Sprint(i))] = issuerSentAgentFirst
					s.sentEntries++
				}
				s.recordSent("reader", origin, nil, []byte(agentBlob), true, now)
			case "total":
				s.sentEntries = issuerSentAllMaxEntries
				s.recordSent("reader", origin, nil, []byte(agentBlob), true, now)
				s.sentEntries = 0 // release simulated peer occupancy
			case "stream":
				s.freezeIDDestinationLocked(bucket, issuerHistoryStream)
			}
			if bucket.block == issuerHistoryComplete || bucket.sent != nil {
				t.Fatal("history was not permanently compacted")
			}
			if !s.serverIDIssued("reader", origin, serverIDListed) {
				t.Fatal("freeze revoked established proof")
			}
			s.mintServerID("reader", origin, serverIDOther, now)
			if s.serverIDIssued("reader", origin, serverIDOther) {
				t.Fatal("freeze allowed new learning")
			}
			s.recordSent("reader", origin, nil, []byte(agentBlob), true, now)
			s.mintServerID("reader", origin, agentBlob, now)
			if bucket.sent != nil || s.serverIDIssued("reader", origin, agentBlob) {
				t.Fatal("post-freeze send reopened reflection history")
			}
			s.mintServerID("reader", other, serverIDOther, now)
			if !s.serverIDIssued("reader", other, serverIDOther) {
				t.Fatal("destination freeze affected unrelated host")
			}
			s.recordSent("peer", origin, nil, nil, true, now)
			s.mintServerID("peer", origin, serverIDOther, now)
			if !s.serverIDIssued("peer", origin, serverIDOther) {
				t.Fatal("destination freeze affected peer caller")
			}
		})
	}
}

func TestIssuerIDFreezeHostAndOriginBoundaries(t *testing.T) {
	for _, aliases := range [][2]string{
		{"https://GRAPH.vendor.example.:8443/items", "https://graph.vendor.example/items"},
		{"https://bücher.vendor.example/items", "https://xn--bcher-kva.vendor.example/items"},
		{"http://graph.vendor.example:8080/items", "https://graph.vendor.example/items"},
	} {
		t.Run(aliases[0], func(t *testing.T) {
			s := newTestServerIDStore(t)
			alias := mustIssuerQueryURL(t, aliases[0])
			origin := mustIssuerQueryURL(t, aliases[1])
			now := time.Now()
			s.recordSent("reader", origin, nil, nil, true, now)
			s.mintServerID("reader", origin, serverIDListed, now)
			s.recordSent("reader", alias, nil, []byte(agentBlob), true, now)
			s.mintServerID("reader", origin, agentBlob, now)
			if s.serverIDIssued("reader", origin, agentBlob) {
				t.Fatal("host alias hid caller-first send")
			}
			s.recordSent("reader", alias, nil, nil, false, now)
			s.mintServerID("reader", origin, serverIDOther, now)
			if s.serverIDIssued("reader", origin, serverIDOther) || !s.serverIDIssued("reader", origin, serverIDListed) {
				t.Fatal("host alias escaped freeze or revoked known proof")
			}
			foreign := *origin
			foreign.Host = origin.Hostname() + ":9443"
			if s.serverIDIssued("reader", &foreign, serverIDListed) || s.serverIDIssued("peer", origin, serverIDListed) {
				t.Fatal("known proof escaped port or caller binding")
			}
		})
	}
}

func TestIssuerIDAdmissionMonotonic(t *testing.T) {
	s := newTestServerIDStore(t)
	now := time.Now()
	for i := range issuerUnreadableMaxSessions {
		origin := mustIssuerQueryURL(t, fmt.Sprintf("https://host-%d.vendor.example/items", i))
		s.recordSent("reader", origin, nil, []byte(agentBlob), true, now)
	}
	refused := mustIssuerQueryURL(t, "https://refused.vendor.example/items")
	s.recordSent("reader", refused, nil, []byte(serverIDOther), true, now)
	if !s.idAdmissionClosed || s.idDestinationLocked("reader", refused) != nil {
		t.Fatal("capacity did not latch refusal")
	}
	for _, bucket := range s.history["reader"].destinations {
		s.freezeIDDestinationLocked(bucket, issuerHistoryUnreadBody)
	}
	if s.sentEntries != 0 {
		t.Fatal("frozen history did not refund token memory")
	}
	// Model a later metadata compaction. The explicit latch must still keep
	// unrecorded sends from becoming apparently fresh, regardless of counts.
	s.idDestinations--
	s.recordSent("reader", refused, nil, nil, true, now)
	s.mintServerID("reader", refused, serverIDOther, now)
	if s.idDestinationLocked("reader", refused) != nil || s.serverIDIssued("reader", refused, serverIDOther) {
		t.Fatal("refused destination reopened after memory refund")
	}
}

func TestIssuerIDUnknownDestinationFreezesCaller(t *testing.T) {
	for _, transport := range []string{"record", "stream"} {
		for _, target := range []*url.URL{nil, {Scheme: "https"}} {
			t.Run(fmt.Sprintf("%s/%v", transport, target), func(t *testing.T) {
				p, cfg := newSentIssuerProxy(t)
				s := p.issuerStoreForUnmediatedSend()
				key := sessionKeyFor(cfg, "reader", "192.0.2.1", envelope.ActorAuthBound)
				origin := mustIssuerQueryURL(t, "https://graph.vendor.example/items")
				now := time.Now()
				s.recordSent(key, origin, nil, nil, true, now)
				s.mintServerID(key, origin, serverIDListed, now)
				if transport == "record" {
					s.recordSent(key, target, nil, nil, false, now)
				} else {
					p.taintIssuerSessionForStream(cfg, "reader", "192.0.2.1", envelope.ActorAuthBound, target)
				}
				later := mustIssuerQueryURL(t, "https://later.vendor.example/items")
				s.recordSent(key, later, nil, nil, true, now)
				s.mintServerID(key, later, serverIDOther, now)
				if s.serverIDIssued(key, later, serverIDOther) || !s.serverIDIssued(key, origin, serverIDListed) {
					t.Fatal("unknown destination reopened learning or revoked proof")
				}
				// A destination admitted before the fallback keeps a compacted
				// bucket; only the caller freeze stops it learning again.
				s.recordSent(key, origin, nil, []byte(agentBlob), true, now)
				s.mintServerID(key, origin, serverIDCreated, now)
				s.mintServerID(key, origin, agentBlob, now)
				if s.serverIDIssued(key, origin, serverIDCreated) || s.serverIDIssued(key, origin, agentBlob) {
					t.Fatal("caller freeze let an existing destination learn")
				}
			})
		}
	}
}

func TestIssuerIDEvictionProtectsFrozen(t *testing.T) {
	for _, frozenCount := range []int{10, issuerCookieMaxEntries} {
		t.Run(fmt.Sprint(frozenCount), func(t *testing.T) {
			s := newTestServerIDStore(t)
			graph := mustIssuerQueryURL(t, "https://graph.vendor.example/items")
			other := mustIssuerQueryURL(t, "https://other.vendor.example/items")
			now := time.Now()
			s.recordSent("reader", graph, nil, nil, true, now)
			s.recordSent("reader", other, nil, nil, true, now)
			for i := range issuerCookieMaxEntries {
				origin := other
				if i < frozenCount {
					origin = graph
				}
				s.mintServerID("reader", origin, fmt.Sprintf("object-identifier-%016d", i), now)
			}
			s.recordSent("reader", graph, nil, nil, false, now)
			s.mintServerID("reader", other, serverIDOther, now)
			for i := range frozenCount {
				if !s.serverIDIssued("reader", graph, fmt.Sprintf("object-identifier-%016d", i)) {
					t.Fatal("another host evicted irreplaceable frozen proof")
				}
			}
			if got := s.serverIDIssued("reader", other, serverIDOther); got != (frozenCount < issuerCookieMaxEntries) {
				t.Fatal("full pinned cache did not refuse only the new proof")
			}
			if s.idCount("reader") != issuerCookieMaxEntries {
				t.Fatal("eviction changed cache capacity")
			}
		})
	}
}

func TestIssuerIDFreezeConcurrent(t *testing.T) {
	s := newTestServerIDStore(t)
	origin := mustIssuerQueryURL(t, "https://graph.vendor.example/items")
	now := time.Now()
	s.recordSent("reader", origin, nil, nil, true, now)
	s.mintServerID("reader", origin, serverIDListed, now)
	var wg sync.WaitGroup
	wg.Go(func() { s.recordSent("reader", origin, nil, nil, false, now) })
	wg.Go(func() {
		for range 32 {
			if !s.serverIDIssued("reader", origin, serverIDListed) {
				t.Error("concurrent freeze revoked proof")
			}
			s.mintServerID("reader", origin, serverIDOther, now)
		}
	})
	wg.Wait()
	s.mintServerID("reader", origin, agentBlob, now)
	if s.serverIDIssued("reader", origin, agentBlob) {
		t.Fatal("learning resumed after concurrent freeze")
	}
}

func TestIssuerIDFreezeCompactionAndRefresh(t *testing.T) {
	s := newTestServerIDStore(t)
	origin := mustIssuerQueryURL(t, "https://graph.vendor.example/items")
	now := time.Now()
	s.recordSent("reader", origin, nil, []byte(agentBlob), true, now)
	s.mintServerID("reader", origin, serverIDListed, now)
	bucket := s.idDestinationLocked("reader", origin)
	before := s.sentEntries
	if before != 1 {
		t.Fatalf("fixture entries = %d", before)
	}
	s.freezeIDDestinationLocked(bucket, issuerHistoryUnreadBody)
	if s.sentEntries != 0 {
		t.Fatal("compaction did not refund exact token count")
	}
	s.freezeIDDestinationLocked(bucket, issuerHistoryStream)
	if s.sentEntries != 0 || bucket.block != issuerHistoryUnreadBody {
		t.Fatal("repeat freeze changed first cause or accounting")
	}
	s.mintServerID("reader", origin, serverIDListed, now)
	if s.idCount("reader") != 1 || !s.serverIDIssued("reader", origin, serverIDListed) {
		t.Fatal("frozen redelivery did not refresh existing proof only")
	}
	s.mintServerID("reader", origin, serverIDOther, now)
	if s.idCount("reader") != 1 {
		t.Fatal("frozen redelivery created new proof")
	}
}

func TestIssuerIDTotalLimitFreezesRequester(t *testing.T) {
	s := newTestServerIDStore(t)
	origin := mustIssuerQueryURL(t, "https://graph.vendor.example/items")
	other := mustIssuerQueryURL(t, "https://other.vendor.example/items")
	now := time.Now()
	s.recordSent("reader", origin, nil, []byte(agentBlob), true, now)
	s.recordSent("reader", other, nil, nil, true, now)
	s.mintServerID("reader", origin, serverIDListed, now)
	// The rest of the pool represents other destinations' retained digests.
	s.sentEntries = issuerSentAllMaxEntries - 1
	s.recordSent("reader", origin, nil, []byte(serverIDOther+" "+serverIDCreated), true, now)
	if s.sentEntries != issuerSentAllMaxEntries-2 {
		t.Fatalf("refund count = %d", s.sentEntries)
	}
	if !s.mintBlockedLocked("reader", origin) || s.mintBlockedLocked("reader", other) {
		t.Fatal("total limit froze the wrong scope")
	}
	s.recordSent("reader", other, nil, []byte(serverIDOther), true, now)
	s.mintServerID("reader", other, serverIDCreated, now)
	if !s.serverIDIssued("reader", other, serverIDCreated) || !s.serverIDIssued("reader", origin, serverIDListed) {
		t.Fatal("refund failed to preserve unrelated learning or known proof")
	}
}

func TestIssuerIDUnknownDestinationDiagnostics(t *testing.T) {
	p, cfg := newSentIssuerProxy(t)
	ic := &InterceptContext{Proxy: p, Config: cfg, Agent: "reader", ClientIP: "192.0.2.1", ActorAuth: envelope.ActorAuthBound}
	origin := mustIssuerQueryURL(t, "https://graph.vendor.example/items")
	if got := ic.issuerIDBlockReason(nil); got != "destination_unknown" {
		t.Fatal(got)
	}
	s := p.issuerStoreForUnmediatedSend()
	key := sessionKeyFor(cfg, ic.Agent, ic.ClientIP, ic.ActorAuth)
	s.recordSent(key, nil, nil, nil, false, time.Now())
	if got := ic.issuerIDBlockReason(origin); got != "caller_learning_frozen" {
		t.Fatal(got)
	}
}

func TestInterceptGraphShapeLifecycle(t *testing.T) {
	h := newWebPlatformHarness(t)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1.0/drive/root/children" {
			_, _ = io.WriteString(w, `{"value":[{"id":"`+serverIDListed+`"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(upstream.Close)
	const agent = "reader"
	if h.send(upstream, http.MethodGet, "/v1.0/drive/root/children", agent, "", "") != http.StatusOK {
		t.Fatal("discovery failed")
	}
	store := h.p.issuerCookieRuntime.Load().query
	key := sessionKeyFor(h.cfg, agent, "10.0.0.1", envelope.ActorAuthBound)
	llm := mustIssuerQueryURL(t, "https://api.llm.vendor.example/messages")
	store.recordSent(key, llm, nil, []byte(strings.Repeat(agentBlob+" ", issuerSentMaxTokensPerRequest+1)), true, time.Now())
	itemPath := "/v1.0/drive/items/" + serverIDListed + "/content"
	if got := h.send(upstream, http.MethodGet, itemPath, agent, "", ""); got != http.StatusOK {
		t.Fatalf("unrelated workload revoked item: %d", got)
	}
	origin := mustIssuerQueryURL(t, upstream.URL)
	store.recordSent(key, origin, nil, nil, false, time.Now())
	if got := h.send(upstream, http.MethodGet, itemPath, agent, "", ""); got != http.StatusOK {
		t.Fatalf("own freeze revoked known item: %d", got)
	}
	store.mintServerID(key, origin, serverIDOther, time.Now())
	if got := h.send(upstream, http.MethodGet, "/v1.0/drive/items/"+serverIDOther+"/content", agent, "", ""); got != http.StatusForbidden {
		t.Fatalf("frozen new item = %d", got)
	}
}

func TestIssuerIDFetchRedirectRecordsDestination(t *testing.T) {
	p, cfg, sc := redirectPolicyTestProxy(t)
	ctx := context.WithValue(t.Context(), ctxKeyAgentConfig, cfg)
	ctx = context.WithValue(ctx, ctxKeyAgentScanner, sc)
	ctx = context.WithValue(ctx, ctxKeyAgent, "reader")
	ctx = context.WithValue(ctx, ctxKeyAgentAuth, string(envelope.ActorAuthBound))
	ctx = context.WithValue(ctx, ctxKeyClientIP, "192.0.2.1")
	original := httptest.NewRequestWithContext(ctx, http.MethodGet, "https://api.vendor.example/start", nil)
	redirect := httptest.NewRequestWithContext(ctx, http.MethodGet, "https://api.vendor.example/next", nil)
	redirect.Header.Set("X-Criteria", agentBlob)
	store := p.issuerStoreForUnmediatedSend()
	if store == nil {
		t.Fatal("fixture has no issuer store")
	}
	key := sessionKeyFor(cfg, "reader", "192.0.2.1", envelope.ActorAuthBound)
	origin := original.URL
	store.recordSent(key, origin, nil, nil, true, time.Now())
	if err := p.client.CheckRedirect(redirect, []*http.Request{original}); err != nil {
		t.Fatal(err)
	}
	store.mintServerID(key, origin, agentBlob, time.Now())
	if store.serverIDIssued(key, origin, agentBlob) {
		t.Fatal("redirect header reflection minted")
	}
	store.mintServerID(key, origin, serverIDOther, time.Now())
	if !store.serverIDIssued(key, origin, serverIDOther) {
		t.Fatal("redirect did not establish complete destination history")
	}
}

func TestIssuerIDOpaqueConnectFreezesBeforeDial(t *testing.T) {
	upstream := newIPv4Server(t, http.NotFoundHandler())
	t.Cleanup(upstream.Close)
	target := mustIssuerQueryURL(t, upstream.URL)
	const host = "api.vendor.example"
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.ForwardProxy.Enabled = true
	cfg.TLSInterception.Enabled = true
	cfg.TLSInterception.PassthroughDomains = []string{host}
	cfg.DefaultAgentIdentity = "reader"
	cfg.BindDefaultAgentIdentity = true
	cfg.APIAllowlist = nil
	cfg.DNS.HostOverrides = map[string][]string{host: {"127.0.0.1"}}
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	store := p.issuerStoreForUnmediatedSend()
	origin := mustIssuerQueryURL(t, "https://"+host+":"+target.Port()+"/items")
	key := sessionKeyFor(cfg, "reader", "192.0.2.1", envelope.ActorAuthConfigDefault)
	store.recordSent(key, origin, nil, nil, true, time.Now())
	store.mintServerID(key, origin, serverIDListed, time.Now())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, origin.String(), nil)
	req.Host = origin.Host
	req.RemoteAddr = "192.0.2.1:12345"
	// A recorder cannot hijack. Even this failed opaque handshake must freeze
	// before any unrecorded send, without depending on a successful splice.
	p.handleConnect(httptest.NewRecorder(), req)
	if !store.mintBlockedLocked(key, origin) {
		t.Fatal("opaque CONNECT left destination learning active")
	}
	if !store.serverIDIssued(key, origin, serverIDListed) {
		t.Fatal("opaque CONNECT revoked exact proof")
	}
	// The tunnel may still be open after an enabled reload starts
	// intercepting the host, so that reload must not reopen learning.
	next := cfg.Clone()
	next.TLSInterception.PassthroughDomains = nil
	if !p.Reload(next, scanner.MustNew(next)) {
		t.Fatal("enabled reload failed")
	}
	live := p.issuerStoreForUnmediatedSend()
	if live != store {
		t.Fatal("enabled reload replaced issuer history")
	}
	live.recordSent(key, origin, nil, nil, true, time.Now())
	live.mintServerID(key, origin, serverIDOther, time.Now())
	if live.serverIDIssued(key, origin, serverIDOther) || !live.serverIDIssued(key, origin, serverIDListed) {
		t.Fatal("removing passthrough reopened learning or revoked proof")
	}
}
