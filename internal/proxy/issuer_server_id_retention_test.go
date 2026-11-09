// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestIssuerIDRetention(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	now := time.Now()
	for _, refresh := range []string{"use", "listing"} {
		t.Run(refresh, func(t *testing.T) {
			s := newTestServerIDStore(t)
			s.recordSent("reader", origin, nil, nil, true, now)
			s.mintServerID("reader", origin, serverIDListed, now)
			if !s.serverIDIssued("reader", origin, serverIDListed) {
				t.Fatal("positive control: issued ID unavailable")
			}
			use := *origin
			use.Path += "/" + serverIDListed
			s.recordSent("reader", &use, nil, nil, true, now)
			for i := range issuerCookieMaxEntries {
				if refresh == "use" {
					if !s.serverIDIssued("reader", origin, serverIDListed+":") {
						t.Fatal("recently used ID was evicted")
					}
				} else {
					s.mintServerID("reader", origin, serverIDListed, now)
				}
				s.mintServerID("reader", origin, fmt.Sprintf("object-identifier-%016d", i), now)
			}
			if !s.serverIDIssued("reader", origin, serverIDListed) {
				t.Fatal("active ID did not survive cache pressure")
			}
			if len(s.ids["reader"]) != issuerCookieMaxEntries {
				t.Fatal("retention changed the allowance capacity")
			}
			if s.serverIDIssued("reader", origin, "object-identifier-0000000000000000") {
				t.Fatal("inactive ID retained instead of active ID")
			}
		})
	}
}

func TestIssuerIDReintroduction(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	for _, value := range []string{serverIDListed, compositeSiteID, serverIDListed + ":"} {
		t.Run(value, func(t *testing.T) {
			s := newTestServerIDStore(t)
			now := time.Now()
			s.recordSent("reader", origin, nil, nil, true, now)
			s.mintServerID("reader", origin, value, now)
			if !s.serverIDIssued("reader", origin, value) {
				t.Fatal("positive control: listing did not issue ID")
			}
			use := *origin
			use.Path += "/" + value + ":/report.txt"
			s.recordSent("reader", &use, nil, nil, true, now)
			for i := range issuerCookieMaxEntries {
				s.mintServerID("reader", origin, fmt.Sprintf("other-identifier-%016d", i), now)
			}
			if s.serverIDIssued("reader", origin, value) {
				t.Fatal("positive control: unused ID was not evicted")
			}
			s.mintServerID("reader", origin, value, now)
			if !s.serverIDIssued("reader", origin, value) {
				t.Fatal("fresh listing did not restore previously used ID")
			}
			if s.serverIDIssued("reader", nil, value) {
				t.Fatal("missing destination acquired restored authority")
			}
			foreign := mustIssuerQueryURL(t, "https://other.vendor.example/items")
			if s.serverIDIssued("reader", foreign, value) || s.serverIDIssued("peer", origin, value) {
				t.Fatal("restored ID escaped its origin or caller")
			}
		})
	}
}

func TestIssuerIDReintroductionKeepsAgentFirst(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	s := newTestServerIDStore(t)
	now := time.Now()
	s.recordSent("reader", origin, nil, []byte(serverIDOther), true, now)
	composite := serverIDOther + "," + serverIDListed
	s.mintServerID("reader", origin, composite, now)
	if !s.serverIDIssued("reader", origin, composite) {
		t.Fatal("positive control: composite with introduced word not issued")
	}
	use := *origin
	use.Path += "/" + composite
	s.recordSent("reader", &use, nil, nil, true, now)
	for i := range issuerCookieMaxEntries {
		s.mintServerID("reader", origin, fmt.Sprintf("other-identifier-%016d", i), now)
	}
	s.mintServerID("reader", origin, serverIDOther, now)
	if s.serverIDIssued("reader", origin, serverIDOther) {
		t.Fatal("legitimate composite use upgraded an agent-first word")
	}
	s.mintServerID("reader", origin, composite, now)
	if !s.serverIDIssued("reader", origin, composite) {
		t.Fatal("server-first word was lost with an agent-first sibling")
	}
}

func TestIssuerIDReintroductionReload(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	p, cfg := newSentIssuerProxy(t)
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	key := sessionKeyFor(cfg, "reader", "192.0.2.1", envelope.ActorAuthBound)
	s := p.issuerCookieRuntime.Load().query
	now := time.Now()
	s.recordSent(key, origin, nil, nil, true, now)
	s.mintServerID(key, origin, serverIDListed, now)
	use := *origin
	use.Path += "/" + serverIDListed
	s.recordSent(key, &use, nil, nil, true, now)
	for i := range issuerCookieMaxEntries {
		s.mintServerID(key, origin, fmt.Sprintf("other-identifier-%016d", i), now)
	}
	next := cfg.Clone()
	if !p.Reload(next, scanner.MustNew(next)) {
		t.Fatal("enabled reload failed")
	}
	live := p.issuerCookieRuntime.Load().query
	if live.serverIDIssued(key, origin, serverIDListed) {
		t.Fatal("reload revived evicted authority without a listing")
	}
	live.mintServerID(key, origin, serverIDListed, now)
	if !live.serverIDIssued(key, origin, serverIDListed) {
		t.Fatal("enabled reload lost introduction provenance")
	}
}

func TestInterceptIssuedIDReintroduction(t *testing.T) {
	h := newWebPlatformHarness(t)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/list" {
			_, _ = io.WriteString(w, `{"id":"`+compositeSiteID+`"}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(upstream.Close)
	const agent = "reader"
	path := "/sites/" + compositeSiteID + "/drives"
	if h.send(upstream, http.MethodGet, "/list", agent, "", "") != http.StatusOK ||
		h.send(upstream, http.MethodGet, path, agent, "", "") != http.StatusOK {
		t.Fatal("positive control: discovery and first use must succeed")
	}
	s := h.p.issuerCookieRuntime.Load().query
	key := sessionKeyFor(h.cfg, agent, "10.0.0.1", envelope.ActorAuthBound)
	origin := mustIssuerQueryURL(t, upstream.URL)
	for i := range issuerCookieMaxEntries {
		s.mintServerID(key, origin, fmt.Sprintf("other-identifier-%016d", i), time.Now())
	}
	if got := h.send(upstream, http.MethodGet, path, agent, "", ""); got != http.StatusForbidden {
		t.Fatalf("evicted ID without discovery = %d, want 403", got)
	}
	if h.send(upstream, http.MethodGet, "/list", agent, "", "") != http.StatusOK ||
		h.send(upstream, http.MethodGet, path, agent, "", "") != http.StatusOK {
		t.Fatal("fresh delivered listing did not restore used, evicted ID")
	}
}

// Sending an ID to another origin of the same host is a caller-first send:
// the ID was issued only on its own scheme and port.
func TestIssuerIDProvenanceIsOriginBound(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	for _, elsewhere := range []string{
		"https://api.vendor.example:8443/items/",
		"http://api.vendor.example/items/",
	} {
		t.Run(elsewhere, func(t *testing.T) {
			s := newTestServerIDStore(t)
			now := time.Now()
			s.recordSent("reader", origin, nil, nil, true, now)
			s.mintServerID("reader", origin, serverIDListed, now)
			if !s.serverIDIssued("reader", origin, serverIDListed) {
				t.Fatal("positive control: listing did not issue ID")
			}
			s.recordSent("reader", mustIssuerQueryURL(t, elsewhere+serverIDListed), nil, nil, true, now)
			digest, _ := s.sentDigest(origin, serverIDListed)
			if got := s.sent["reader"][digest]; got != issuerSentAgentFirst {
				t.Fatalf("send to another origin recorded provenance %d", got)
			}
			for i := range issuerCookieMaxEntries {
				s.mintServerID("reader", origin, fmt.Sprintf("other-identifier-%016d", i), now)
			}
			s.mintServerID("reader", origin, serverIDListed, now)
			if s.serverIDIssued("reader", origin, serverIDListed) {
				t.Fatal("caller-first send on another origin restored the ID")
			}
		})
	}
}

// Use, eviction and sends race on one caller. Whatever the interleaving, a
// word the caller sent first never becomes server-first.
func TestIssuerIDProvenanceConcurrent(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	s := newTestServerIDStore(t)
	now := time.Now()
	s.recordSent("reader", origin, nil, []byte(serverIDOther), true, now)
	composite := serverIDOther + "," + serverIDListed
	s.mintServerID("reader", origin, composite, now)
	use := mustIssuerQueryURL(t, "https://api.vendor.example/items/"+composite+":/report.txt")
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 400 {
				switch worker {
				case 0:
					s.serverIDIssued("reader", origin, composite+":")
				case 1:
					s.recordSent("reader", use, nil, nil, true, now)
				case 2:
					s.mintServerID("reader", origin, fmt.Sprintf("other-identifier-%016d", i*8+worker), now)
				default:
					s.mintServerID("reader", origin, composite, now)
				}
			}
		}()
	}
	wg.Wait()
	other, _ := s.sentDigest(origin, serverIDOther)
	if got := s.sent["reader"][other]; got != issuerSentAgentFirst {
		t.Fatalf("agent-first word provenance = %d", got)
	}
	if len(s.ids["reader"]) > issuerCookieMaxEntries {
		t.Fatal("allowances exceeded capacity")
	}
	s.mintServerID("reader", origin, serverIDOther, now)
	if s.serverIDIssued("reader", origin, serverIDOther) {
		t.Fatal("agent-first word became an issued ID")
	}
}
