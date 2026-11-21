// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// joinedCardHalves is a Luhn-valid test card split into two values that look
// like adjacent record IDs. Neither value is a card on its own.
func joinedCardHalves() (string, string) {
	return "4" + strings.Repeat("1", 7), strings.Repeat("1", 8)
}

const joinedDetailPath = "/records/detail"

func joinedDetailURL(host, query string) string {
	return "https://" + host + joinedDetailPath + "?" + query
}

// servePage makes the source origin answer with an HTML document linking
// every href.
func (e *delegationEnv) servePage(hrefs ...string) {
	e.issue(http.StatusOK)
	var links strings.Builder
	for _, href := range hrefs {
		links.WriteString(`<a href="` + strings.ReplaceAll(href, "&", "&amp;") + `">open</a>`)
	}
	body := `<!doctype html><html><body>` + links.String() + `</body></html>`
	e.sourcePayload.Store(&struct{ contentType, body string }{"text/html; charset=utf-8", body})
}

// visit loads the page as agent-one so its links become issuer evidence.
func (e *delegationEnv) visit() {
	e.t.Helper()
	if got := e.do("agent-one", http.MethodGet, "https://"+delegationSourceHost+"/records/list"); got != http.StatusOK {
		e.t.Fatalf("page status = %d, want 200", got)
	}
}

func TestInterceptIssuedJoinedViewDLP(t *testing.T) {
	first, second := joinedCardHalves()
	query := "wo=" + first + "&site=" + second
	issued := joinedDetailURL(delegationSourceHost, query)

	t.Run("baseline: the joined IDs block as a card", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		if got := e.do("agent-one", http.MethodGet, issued); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: the premise of every other case", got)
		}
	})

	t.Run("a link the origin served passes", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(joinedDetailPath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issued); got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
	})

	t.Run("relief is scoped to the session that saw the page", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(joinedDetailPath + "?" + query)
		e.visit()
		if got := e.do("agent-two", http.MethodGet, issued); got != http.StatusForbidden {
			t.Fatalf("other session status = %d, want 403", got)
		}
	})

	t.Run("one value without evidence keeps the joined view", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(joinedDetailPath + "?wo=" + first + "&site=" + strings.Repeat("9", 8))
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issued); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: the agent chose the second half", got)
		}
	})

	t.Run("an added value without evidence keeps the joined view", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(joinedDetailPath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issued+"&x=1"); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	// A hostile origin can serve each chunk of a secret in its own link. The
	// agent recombining those individually issued values into one query is
	// exactly the split exfiltration the joined views exist to catch.
	t.Run("recombined chunks from separate served links still block", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(joinedDetailPath+"?wo="+first+"&page=1", joinedDetailPath+"?site="+second+"&page=2")
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issued); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("reordered pairs of a served link still block", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(joinedDetailPath + "?site=" + second + "&wo=" + first)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issued); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("a duplicated key on a served link still blocks", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(joinedDetailPath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issued+"&wo="+first); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("values issued by one host do not travel to another", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(joinedDetailPath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, joinedDetailURL("elsewhere.vendor.example", query)); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("values issued for one path do not cover another", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(joinedDetailPath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, "https://"+delegationSourceHost+"/records/other?"+query); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	// A whole card the page itself served would be returned to the site that
	// issued it and is relieved by the issued-value rule. One the page did not
	// serve, beside a served value, keeps its per-value block.
	t.Run("a whole card in a value the page did not serve still blocks", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		single := "wo=" + first + second + "&site=1"
		e.servePage(joinedDetailPath + "?wo=" + strings.Repeat("7", 8) + "&site=1")
		e.visit()
		if got := e.do("agent-one", http.MethodGet, joinedDetailURL(delegationSourceHost, single)); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("canary in an issued value still blocks", func(t *testing.T) {
		e := newSameOriginEnv(t, configureBrowserCanary)
		withCanary := query + "&ref=" + browserCanaryFixture
		e.servePage(joinedDetailPath + "?" + withCanary)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, joinedDetailURL(delegationSourceHost, withCanary)); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("environment secret in an issued value still blocks", func(t *testing.T) {
		secret := strings.Join([]string{"Zq8", "Lr2", "Vx9", "Pm4", "Tn7", "Kw3", "Hs6"}, "")
		t.Setenv("PIPELOCK_JOINED_VIEW_TEST_SECRET", secret)
		e := newSameOriginEnv(t, func(c *config.Config) { c.DLP.ScanEnv = true })
		withSecret := query + "&ref=" + secret
		e.servePage(joinedDetailPath + "?" + withSecret)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, joinedDetailURL(delegationSourceHost, withSecret)); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("disabled issuer evidence gives no relief", func(t *testing.T) {
		e := newSameOriginEnv(t, func(c *config.Config) { c.RequestBodyScanning.IssuerBoundSessionCookies = false })
		e.servePage(joinedDetailPath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issued); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("reload: unrelated change keeps evidence, disabling revokes it", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(joinedDetailPath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issued); got != http.StatusOK {
			t.Fatalf("first load status = %d, want 200", got)
		}
		unrelated := e.cfg.Clone()
		unrelated.FetchProxy.Monitoring.MaxReqPerMinute++
		e.reload(unrelated)
		if got := e.do("agent-one", http.MethodGet, issued); got != http.StatusOK {
			t.Fatalf("after unrelated reload status = %d, want 200", got)
		}
		off := e.cfg.Clone()
		off.RequestBodyScanning.IssuerBoundSessionCookies = false
		e.reload(off)
		if got := e.do("agent-one", http.MethodGet, issued); got != http.StatusForbidden {
			t.Fatalf("after disabling reload status = %d, want 403", got)
		}
	})
}
