// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// newSameOriginEnv is the delegation harness with no operator delegation at
// all: every relief below must come from issuer evidence the origin itself
// produced.
func newSameOriginEnv(t *testing.T, mutate func(*config.Config)) *delegationEnv {
	t.Helper()
	return newDelegationEnv(t, func(c *config.Config) {
		c.FetchProxy.Monitoring.IssuedRedirectDelegations = nil
		if mutate != nil {
			mutate(c)
		}
	})
}

// reload swaps the proxy's live policy the way a config reload does and makes
// later requests use the new snapshot and scanner.
func (e *delegationEnv) reload(c *config.Config) {
	e.t.Helper()
	sc := scanner.MustNew(c)
	e.t.Cleanup(sc.Close)
	if !e.p.Reload(c, sc) {
		e.t.Fatal("reload refused")
	}
	e.cfg, e.sc = c, sc
}

// challengeURL models an anti-abuse interstitial a search origin redirects
// to on itself: a return URL plus an opaque, server-minted token.
func challengeURL(host string) string {
	return "https://" + host + "/sorry/index?continue=" +
		url.QueryEscape("https://"+host+"/search?q=weather") + "&q=" + issuedTestToken()
}

// TestInterceptSameOriginRedirect pins that a server's redirect to itself
// needs no issued_redirect_delegations entry: the Location's path and query
// values are recorded as that origin's own issuer evidence, so the browser can
// follow an anti-abuse interstitial carrying a minted token.
func TestInterceptSameOriginRedirect(t *testing.T) {
	sameOrigin := challengeURL(delegationSourceHost)

	t.Run("baseline: the challenge URL is blocked without evidence", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		if got := e.do("agent-one", http.MethodGet, sameOrigin); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: the premise of every other case", got)
		}
	})

	t.Run("a same-origin Location is relieved with no delegation", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.issue(http.StatusFound, sameOrigin)
		// The source answers every request with the redirect, so a relieved
		// follow-up also returns 302; only 403 means the proxy refused it.
		if got := e.issueAndFollow(sameOrigin); got != http.StatusFound {
			t.Fatalf("follow-up status = %d, want 302 from upstream", got)
		}
		if got := e.do("agent-two", http.MethodGet, sameOrigin); got != http.StatusForbidden {
			t.Fatalf("other session status = %d, want 403", got)
		}
	})

	t.Run("relative Location resolves to the same origin", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		u, _ := url.Parse(sameOrigin)
		e.issue(http.StatusSeeOther, u.RequestURI())
		if got := e.issueAndFollow(sameOrigin); got != http.StatusSeeOther {
			t.Fatalf("follow-up status = %d, want 303 from upstream", got)
		}
	})

	t.Run("only the exact issued URL is relieved", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.issue(http.StatusFound, sameOrigin)
		_ = e.issueAndFollow(sameOrigin)
		altered := strings.Replace(sameOrigin, issuedTestToken(), strings.ToUpper(issuedTestToken()), 1)
		if got := e.do("agent-one", http.MethodGet, altered); got != http.StatusForbidden {
			t.Fatalf("altered token status = %d, want 403", got)
		}
		extra := sameOrigin + "&leak=" + strings.ToLower(issuedTestToken())
		if got := e.do("agent-one", http.MethodGet, extra); got != http.StatusForbidden {
			t.Fatalf("added parameter status = %d, want 403", got)
		}
	})

	t.Run("cross-origin Location still needs a delegation", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		cross := delegationFilesURL(delegationFilesPath, delegationTicketQuery())
		e.issue(http.StatusFound, cross)
		if got := e.issueAndFollow(cross); got != http.StatusForbidden || e.fileHits.Load() != 0 {
			t.Fatalf("cross-origin follow-up status = %d, file hits = %d, want 403 and 0", got, e.fileHits.Load())
		}
	})

	t.Run("disabled issuer evidence gives no relief", func(t *testing.T) {
		e := newSameOriginEnv(t, func(c *config.Config) { c.RequestBodyScanning.IssuerBoundSessionCookies = false })
		e.issue(http.StatusFound, sameOrigin)
		if got := e.issueAndFollow(sameOrigin); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 with issuer evidence disabled", got)
		}
	})

	t.Run("reload: unrelated change keeps evidence, disabling revokes it", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.issue(http.StatusFound, sameOrigin)
		if got := e.issueAndFollow(sameOrigin); got != http.StatusFound {
			t.Fatalf("first load status = %d, want 302", got)
		}
		unrelated := e.cfg.Clone()
		unrelated.FetchProxy.Monitoring.MaxReqPerMinute++
		e.reload(unrelated)
		if got := e.do("agent-one", http.MethodGet, sameOrigin); got != http.StatusFound {
			t.Fatalf("after unrelated reload status = %d, want 302", got)
		}
		off := e.cfg.Clone()
		off.RequestBodyScanning.IssuerBoundSessionCookies = false
		e.reload(off)
		if got := e.do("agent-one", http.MethodGet, sameOrigin); got != http.StatusForbidden {
			t.Fatalf("after disabling reload status = %d, want 403", got)
		}
	})
}
