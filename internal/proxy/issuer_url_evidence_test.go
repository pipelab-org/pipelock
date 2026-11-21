// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestIssuerURLEvidence(t *testing.T) {
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	issued := parse("https://records.vendor.example/detail?wo=1&site=2")

	t.Run("digest refusals", func(t *testing.T) {
		s := newIssuerQueryStore()
		for name, raw := range map[string]string{
			"no query":       "https://records.vendor.example/detail",
			"cleartext":      "http://records.vendor.example/detail?wo=1",
			"userinfo":       "https://" + url.UserPassword("u", "p").String() + "@records.vendor.example/detail?wo=1",
			"oversize query": "https://records.vendor.example/detail?wo=" + strings.Repeat("a", issuerCookieMaxPairBytes),
		} {
			if _, ok := s.urlDigest(parse(raw)); ok {
				t.Errorf("%s: digest minted", name)
			}
			s.rememberURL("sess", parse(raw), time.Now())
			if s.urlIssued("sess", parse(raw)) {
				t.Errorf("%s: recorded and matched", name)
			}
		}
	})

	t.Run("exact match, session and generation scoped", func(t *testing.T) {
		s := newIssuerQueryStore()
		s.rememberURL("sess", issued, time.Now())
		s.rememberURL("sess", issued, time.Now()) // a repeat refreshes, it does not duplicate
		if got := len(s.urls["sess"]); got != 1 {
			t.Fatalf("entries = %d, want 1", got)
		}
		if !s.urlIssued("sess", issued) {
			t.Fatal("exact served URL not matched")
		}
		for name, raw := range map[string]string{
			"reordered": "https://records.vendor.example/detail?site=2&wo=1",
			"extra":     "https://records.vendor.example/detail?wo=1&site=2&x=3",
			"path":      "https://records.vendor.example/other?wo=1&site=2",
			"host":      "https://elsewhere.vendor.example/detail?wo=1&site=2",
			"port":      "https://records.vendor.example:8443/detail?wo=1&site=2",
			"no query":  "https://records.vendor.example/detail",
		} {
			if s.urlIssued("sess", parse(raw)) {
				t.Errorf("%s matched", name)
			}
		}
		if s.urlIssued("other", issued) || s.urlIssued("", issued) {
			t.Fatal("evidence crossed sessions")
		}
		next := s.nextGeneration()
		if s.urlIssued("sess", issued) {
			t.Fatal("a retired generation still vouched for the URL")
		}
		if next.urlIssued("sess", issued) {
			t.Fatal("a new generation inherited URL evidence")
		}
	})

	t.Run("nil, disabled and empty-session stores grant nothing", func(t *testing.T) {
		var nilStore *issuerQueryStore
		nilStore.rememberURL("sess", issued, time.Now())
		if nilStore.urlIssued("sess", issued) {
			t.Fatal("nil store matched")
		}
		disabled := newIssuerQueryStore()
		disabled.disabled = true
		disabled.rememberURL("sess", issued, time.Now())
		if disabled.urlIssued("sess", issued) || len(disabled.urls) != 0 {
			t.Fatal("disabled store recorded or matched")
		}
		s := newIssuerQueryStore()
		s.rememberURL("", issued, time.Now())
		if len(s.urls) != 0 {
			t.Fatal("empty session recorded")
		}
	})

	t.Run("per-session cap evicts the oldest URL", func(t *testing.T) {
		s := newIssuerQueryStore()
		first := parse("https://records.vendor.example/detail?page=0&x=1")
		s.rememberURL("sess", first, time.Now())
		for i := 1; i <= issuerCookieMaxEntries; i++ {
			s.rememberURL("sess", parse("https://records.vendor.example/detail?page="+strings.Repeat("9", i%7+1)+"&n="+strconv.Itoa(i)), time.Now())
		}
		if got := len(s.urls["sess"]); got != issuerCookieMaxEntries {
			t.Fatalf("entries = %d, want cap %d", got, issuerCookieMaxEntries)
		}
		if s.urlIssued("sess", first) {
			t.Fatal("the oldest URL survived past the cap")
		}
	})

	t.Run("session eviction drops URL evidence", func(t *testing.T) {
		s := newIssuerQueryStore()
		s.rememberURL("victim", issued, time.Now().Add(-time.Hour))
		for i := 0; i < issuerCookieMaxSessions; i++ {
			s.rememberURL("sess-"+strconv.Itoa(i), issued, time.Now())
		}
		if _, kept := s.urls["victim"]; kept {
			t.Fatal("least recently used session kept its URL evidence")
		}
	})
}

func TestIssuerEvidenceGenerationEdges(t *testing.T) {
	runtime := &issuerCookieRuntime{}
	if runtime.sameEvidenceGeneration(nil) || (*issuerCookieRuntime)(nil).sameEvidenceGeneration(runtime) {
		t.Fatal("a missing runtime matched")
	}
	if !runtime.sameEvidenceGeneration(runtime) {
		t.Fatal("a runtime did not match itself")
	}
	if (*InterceptContext)(nil).currentIssuerRuntime() != nil || (&InterceptContext{}).currentIssuerRuntime() != nil {
		t.Fatal("a context without a proxy resolved an issuer runtime")
	}

	base := config.Defaults()
	added := base.Clone()
	added.Agents = map[string]config.AgentProfile{"browser": {SourceCIDRs: []string{"10.0.0.0/24"}}}
	if !issuerIdentitySettingsChanged(base, added) {
		t.Fatal("adding a source-bound agent did not change identity settings")
	}
	if !issuerIdentitySettingsChanged(added, base) {
		t.Fatal("removing a source-bound agent did not change identity settings")
	}
	listener := base.Clone()
	listener.Agents = map[string]config.AgentProfile{"browser": {Listeners: []string{"127.0.0.1:0"}}}
	if !issuerIdentitySettingsChanged(base, listener) {
		t.Fatal("adding a listener-bound agent did not change identity settings")
	}
	unbound := base.Clone()
	unbound.Agents = map[string]config.AgentProfile{"browser": {}}
	if issuerIdentitySettingsChanged(base, unbound) {
		t.Fatal("adding an agent with no identity binding changed identity settings")
	}
}
