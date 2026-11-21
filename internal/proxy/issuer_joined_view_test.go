// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
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

	// The exact served URL relieves only the joined views; a whole card
	// inside one value is still matched by the per-value views.
	t.Run("a whole card in one issued value still blocks", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		single := "wo=" + first + second + "&site=1"
		e.servePage(joinedDetailPath + "?" + single)
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

func TestJoinedViewURLOrigin(t *testing.T) {
	e := newSameOriginEnv(t, nil)
	ic := &InterceptContext{
		Proxy: e.p, Config: e.cfg, Agent: "agent-one", ClientIP: "192.0.2.1", ActorAuth: envelope.ActorAuthBound,
	}
	store := ic.issuerQueryStore()
	session := sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
	const path = "/records/detail?wo=1&site=2"
	issuer := mustIssuerQueryURL(t, "https://api.vendor.example/records/list")
	response := &http.Response{
		StatusCode: http.StatusFound, Request: &http.Request{URL: issuer}, Header: make(http.Header),
	}
	response.Header.Set("Location", "https://api.vendor.example."+path)
	recordDeliveredIssuerQuery(ic, response, nil, true)
	if store.urlIssued(session, mustIssuerQueryURL(t, "https://api.vendor.example."+path)) {
		t.Fatal("a redirect to a distinct browser origin recorded whole-URL evidence")
	}
	response.Header.Set("Location", "https://API.VENDOR.EXAMPLE"+path)
	recordDeliveredIssuerQuery(ic, response, nil, true)
	if !store.urlIssued(session, mustIssuerQueryURL(t, "https://api.vendor.example:443"+path)) {
		t.Fatal("host case and an explicit default port must match the issued origin")
	}
	if store.urlIssued(session, mustIssuerQueryURL(t, "https://api.vendor.example."+path)) {
		t.Fatal("a distinct browser origin reused whole-URL evidence")
	}
	for _, different := range []string{
		"https://api.vendor.example:8443" + path,
		"https://api.vendor.example/records/%64etail?wo=1&site=2",
		"https://api.vendor.example/records/detail?wo=%31&site=2",
	} {
		if store.urlIssued(session, mustIssuerQueryURL(t, different)) {
			t.Errorf("different URL %s reused whole-URL evidence", different)
		}
	}
}

func TestInterceptJoinedViewAndDelegatedEntropyReceipts(t *testing.T) {
	const targetHost = "elsewhere.vendor.example"
	e := newDelegationEnv(t, func(c *config.Config) {
		c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins = []string{"https://" + targetHost}
		c.FlightRecorder.RequireReceipts = true
	})
	rph := newReceiptProxyHelperWithMetrics(t, e.m)
	e.p.receiptEmitterPtr.Store(rph.emitter)
	first, second := joinedCardHalves()
	target := joinedDetailURL(targetHost, "wo="+first+"&site="+second+"&"+delegationTicketQuery())
	e.issue(http.StatusFound, target)
	if got := e.do("agent-one", http.MethodGet, delegationSourceURL()); got != http.StatusFound {
		t.Fatalf("source redirect status = %d, want 302", got)
	}
	targetURL, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	e.servePage(targetURL.RequestURI())
	if got := e.do("agent-one", http.MethodGet, "https://"+targetHost+"/records/list"); got != http.StatusOK {
		t.Fatalf("destination page status = %d, want 200", got)
	}
	if got := e.do("agent-one", http.MethodGet, target); got != http.StatusOK {
		t.Fatalf("issued URL status = %d, want 200", got)
	}
	var joinedReceipt, entropyReceipt bool
	for _, r := range rph.findReceipts(t) {
		switch r.ActionRecord.Layer {
		case issuerJoinedViewReceiptKey:
			joinedReceipt = strings.Contains(string(r.Ext), `"dlp_issuer_joined_view_allow":"issued_joined_view"`)
		case issuerQueryReceiptExtensionKey:
			entropyReceipt = strings.Contains(string(r.Ext), `"entropy_issuer_query_allow":"issued_redirect"`)
		}
	}
	if !joinedReceipt || !entropyReceipt {
		t.Fatalf("receipts for the two allowances: joined DLP = %t, delegated entropy = %t, want both", joinedReceipt, entropyReceipt)
	}
}

func TestNativeCapacityIssuerQueryBatch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		slots int64
		want  int
	}{
		{"refused", nativeRequestRecords + 4, 0},
		{"admitted", nativeRequestRecords + 6, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, emitter, dir := newNativeCapacityProxy(t, tc.slots)
			admission, err := p.reserveReceiptAdmission()
			if err != nil {
				t.Fatal(err)
			}
			defer admission.ReleaseNativeAdmission()
			stopAdmissions := func() {
				t.Helper()
				_, err := emitter.ReserveNativeRecords(int(tc.slots))
				if !errors.Is(err, ael.ErrCapacity) {
					t.Fatalf("expected native receipt capacity stop, got %v", err)
				}
			}
			if tc.want == 0 {
				stopAdmissions()
			}
			ic := &InterceptContext{Proxy: p, Config: p.CurrentConfig(), receiptShard: admission}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/records/detail", http.NoBody)
			kinds := []issuerQueryKind{issuerQueryJoinedView, issuerQueryIssuedRedirect}
			err = ic.recordIssuerQueryAllows(audit.NewRequestLogContext("fixture"), req, req.URL.String(), kinds)
			if (tc.want == 0 && !errors.Is(err, ael.ErrCapacity)) || (tc.want > 0 && err != nil) {
				t.Fatalf("issuer query batch admission = %v", err)
			}
			if tc.want > 0 {
				stopAdmissions()
			}
			admission.ReleaseNativeAdmission()
			if got := verifyNativeCapacityClose(t, emitter, dir); got != tc.want {
				t.Fatalf("issuer query batch wrote %d native records, want %d", got, tc.want)
			}
		})
	}
}
