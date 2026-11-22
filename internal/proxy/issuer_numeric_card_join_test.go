// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const (
	numericJoinOriginHost    = "api.vendor.example"
	numericJoinOtherHost     = "elsewhere.vendor.example"
	numericJoinSubdomainHost = "sub.api.vendor.example"
)

// G101-safe Luhn-valid test cards constructed from split strings.
func numericJoinRealShape19() (string, string) {
	// 11-digit work-order ID + 8-digit site ID = 19-digit Luhn-valid Visa.
	return "42000" + "123456", "7890" + "1239"
}

func numericJoinCard16A() (string, string) {
	// 8+8 = 16-digit Luhn-valid Visa.
	return "4" + strings.Repeat("1", 7), strings.Repeat("1", 8)
}

func numericJoinCard16B() (string, string) {
	// 8+8 = 16-digit Luhn-valid Mastercard.
	return "5105" + "1051", "0510" + "5100"
}

func (e *delegationEnv) serveBody(contentType, body string) {
	e.issue(http.StatusOK)
	e.sourcePayload.Store(&struct{ contentType, body string }{contentType, body})
}

func (e *delegationEnv) doWithAuth(rawURL string, auth envelope.ActorAuth, runtime *issuerCookieRuntime) int {
	e.t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		e.t.Fatal(err)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	resp := interceptAndRequestWithRecorder(e.t, interceptRequestOptions{
		Upstream: e.upstream, TargetHost: u.Hostname(), TargetPort: port, UpstreamRT: e.rt,
		Cache: e.cache, Pool: e.pool, Config: e.cfg, Scanner: e.sc, Logger: e.logger, Metrics: e.m,
		Request: req, Proxy: e.p, Agent: "agent-one", ActorAuth: auth, IssuerRuntime: runtime,
	})
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestInterceptIssuerNumericCardJoin_RealShapePositiveAndReceipts(t *testing.T) {
	woID, siteID := numericJoinRealShape19()
	navURL := "https://" + numericJoinOriginHost + "/records/detail?wo=" + woID + "&site=" + siteID
	interleavedURL := "https://" + numericJoinOriginHost + "/records/detail?wo=" + woID + "&tab=summary&site=" + siteID

	t.Run("baseline blocks JS-built 11+8 navigation before issuance", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		if got := e.do("agent-one", http.MethodGet, navURL); got != http.StatusForbidden {
			t.Fatalf("baseline adjacent status = %d, want 403", got)
		}
		if got := e.do("agent-one", http.MethodGet, interleavedURL); got != http.StatusForbidden {
			t.Fatalf("baseline interleaved status = %d, want 403", got)
		}
	})

	htmlVariants := []struct {
		name string
		html string
	}{
		{"body text", `<!doctype html><html><body><span>Order ` + woID + `</span></body></html>`},
		{"attribute", `<!doctype html><html><body><div data-wo="` + woID + `">open</div></body></html>`},
		{"inline script", `<!doctype html><html><body><script>window.__WO = ` + woID + `;</script></body></html>`},
	}
	jsonVariants := []struct {
		name string
		json string
	}{
		{"json number token", `{"siteId":` + siteID + `,"status":"active"}`},
		{"json string token", `{"siteId":"site:` + siteID + `","status":"active"}`},
	}

	for _, hv := range htmlVariants {
		for _, jv := range jsonVariants {
			t.Run(hv.name+" + "+jv.name, func(t *testing.T) {
				auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
				logger, err := audit.New("json", "file", auditPath, true, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)

				e := newSameOriginEnv(t, func(c *config.Config) {
					c.FlightRecorder.RequireReceipts = true
				})
				e.logger = logger
				e.p.logger = logger
				rph := newReceiptProxyHelperWithMetrics(t, e.m)
				e.p.receiptEmitterPtr.Store(rph.emitter)

				// 1. Origin serves HTML containing 11-digit ID.
				e.serveBody("text/html; charset=utf-8", hv.html)
				if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/records/list"); got != http.StatusOK {
					t.Fatalf("HTML page status = %d, want 200", got)
				}
				// 2. Origin serves JSON containing 8-digit site ID.
				e.serveBody("application/json", jv.json)
				if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/api/sites"); got != http.StatusOK {
					t.Fatalf("JSON response status = %d, want 200", got)
				}
				// 3. JS-built same-origin navigation (exact URL never served) passes on both raw query_concat and query_subsequence.
				if got := e.do("agent-one", http.MethodGet, navURL); got != http.StatusOK {
					t.Fatalf("JS-built adjacent navigation status = %d, want 200", got)
				}
				if got := e.do("agent-one", http.MethodGet, interleavedURL); got != http.StatusOK {
					t.Fatalf("JS-built interleaved navigation status = %d, want 200", got)
				}
				// 4. Other session does not inherit relief.
				if got := e.do("agent-two", http.MethodGet, navURL); got != http.StatusForbidden {
					t.Fatalf("other session status = %d, want 403", got)
				}

				// Verify audit event and absence of sensitive values.
				auditBytes, err := os.ReadFile(filepath.Clean(auditPath))
				if err != nil {
					t.Fatal(err)
				}
				auditText := string(auditBytes)
				if !strings.Contains(auditText, `"event":"dlp_issuer_numeric_card_join_allow"`) {
					t.Fatalf("missing dlp_issuer_numeric_card_join_allow audit event: %s", auditText)
				}
				for _, leaked := range []string{woID, siteID, "wo=", "site="} {
					if strings.Contains(auditText, leaked) {
						t.Fatalf("audit log leaked %q: %s", leaked, auditText)
					}
				}

				// Verify signed receipt with dedicated layer and extension.
				var foundReceipt bool
				for _, r := range rph.findReceipts(t) {
					if r.ActionRecord.Layer == issuerNumericCardJoinReceiptKey &&
						strings.Contains(string(r.Ext), `"dlp_issuer_numeric_card_join_allow":"issued_numeric_card_join"`) {
						foundReceipt = true
					}
				}
				if !foundReceipt {
					t.Fatal("expected signed receipt under dlp_issuer_numeric_card_join_allow with issued_numeric_card_join extension")
				}
			})
		}
	}

	t.Run("require_receipts fails closed when receipt emission fails", func(t *testing.T) {
		e := newSameOriginEnv(t, func(c *config.Config) {
			c.FlightRecorder.RequireReceipts = true
		})
		rph := newReceiptProxyHelperWithMetrics(t, e.m)
		e.p.receiptEmitterPtr.Store(rph.emitter)

		e.serveBody("text/html; charset=utf-8", `<p>`+woID+`</p>`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/records/list"); got != http.StatusOK {
			t.Fatalf("HTML status = %d, want 200", got)
		}
		e.serveBody("application/json", `{"siteId":`+siteID+`}`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/api/sites"); got != http.StatusOK {
			t.Fatalf("JSON status = %d, want 200", got)
		}
		// Control: with the recorder open, the same navigation is relieved, so a
		// later refusal can only come from the receipt path.
		if status, reason := numericJoinDoWithReason(e, "agent-one", navURL); status != http.StatusOK {
			t.Fatalf("control status = %d (reason %q), want 200", status, reason)
		}
		// Close recorder so receipt emission fails on the relieved navigation.
		if err := rph.rec.Close(); err != nil {
			t.Fatal(err)
		}
		status, reason := numericJoinDoWithReason(e, "agent-one", navURL)
		if status != http.StatusForbidden || reason != string(blockreason.ReceiptEmissionFailed) {
			t.Fatalf("require_receipts with closed recorder = %d reason %q, want 403 %q", status, reason, blockreason.ReceiptEmissionFailed)
		}
	})
}

func TestInterceptIssuerNumericCardJoin_AttackMatrix(t *testing.T) {
	cardA1, cardA2 := numericJoinCard16A()
	cardB1, cardB2 := numericJoinCard16B()

	t.Run("non-card credentials recombined still block", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		// Split a fake Anthropic-style token across HTML and JSON responses.
		part1 := "sk-" + "ant-api03-"
		part2 := strings.Repeat("Z", 32)
		e.serveBody("text/html; charset=utf-8", `<p>`+part1+`</p>`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/p1"); got != http.StatusOK {
			t.Fatalf("p1 status = %d, want 200", got)
		}
		e.serveBody("application/json", `{"v":"`+part2+`"}`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/p2"); got != http.StatusOK {
			t.Fatalf("p2 status = %d, want 200", got)
		}
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/exfil?a="+part1+"&b="+part2); got != http.StatusForbidden {
			t.Fatalf("recombined non-card credential status = %d, want 403", got)
		}
	})

	t.Run("short chunks 4x4 6+10 7+9 still block", func(t *testing.T) {
		cases := []struct {
			name   string
			chunks []string
		}{
			{"4x4", []string{"4111", "1111", "1111", "1111"}},
			{"6+10", []string{"411111", strings.Repeat("1", 10)}},
			{"7+9", []string{"4111111", strings.Repeat("1", 9)}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				e := newSameOriginEnv(t, nil)
				e.serveBody("text/html; charset=utf-8", `<p>`+strings.Join(tc.chunks, " ")+`</p>`)
				if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/chunks"); got != http.StatusOK {
					t.Fatalf("serve chunks status = %d, want 200", got)
				}
				var q strings.Builder
				for i, c := range tc.chunks {
					if i > 0 {
						q.WriteByte('&')
					}
					fmt.Fprintf(&q, "p%d=%s", i, c)
				}
				if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/detail?"+q.String()); got != http.StatusForbidden {
					t.Fatalf("%s status = %d, want 403", tc.name, got)
				}
			})
		}
	})

	t.Run("dictionary 0..9 and 00..99 still block", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		var dict strings.Builder
		for i := range 10 {
			fmt.Fprintf(&dict, "%d ", i)
		}
		for i := range 100 {
			fmt.Fprintf(&dict, "%02d ", i)
		}
		e.serveBody("text/html; charset=utf-8", `<p>`+dict.String()+`</p>`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/dict"); got != http.StatusOK {
			t.Fatalf("serve dict status = %d, want 200", got)
		}
		// Assemble 16-digit card from two-digit dictionary values (8 params) and single-digit values.
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/detail?a=41&b=11&c=11&d=11&e=11&f=11&g=11&h=11"); got != http.StatusForbidden {
			t.Fatalf("00..99 dictionary composition status = %d, want 403", got)
		}
	})

	t.Run("agent-first reflected 8+8 blocks across intercept forward fetch and reverse", func(t *testing.T) {
		for _, sendPath := range []string{"intercept", "forward", "fetch", "reverse"} {
			t.Run(sendPath, func(t *testing.T) {
				e := newSameOriginEnv(t, nil)
				target := "https://" + numericJoinOriginHost + "/detail?wo=" + cardA1 + "&site=" + cardA2
				switch sendPath {
				case "intercept":
					e.serveBody("text/html; charset=utf-8", `<p>ok</p>`)
					if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/search?q="+cardA1); got != http.StatusOK {
						t.Fatalf("intercept send status = %d, want 200", got)
					}
				case "forward":
					req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+numericJoinOriginHost+"/submit", strings.NewReader("id="+cardA1))
					e.p.recordIssuerForwardSent(e.cfg, "agent-one", "10.0.0.1", envelope.ActorAuthBound, req, []byte("id="+cardA1))
				case "fetch":
					u := mustIssuerQueryURL(t, "https://"+numericJoinOriginHost+"/fetch?seed="+cardA1)
					e.p.recordIssuerFetchSent(e.cfg, "agent-one", "10.0.0.1", envelope.ActorAuthBound, u)
				case "reverse":
					req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+numericJoinOriginHost+"/rev", strings.NewReader(`{"v":"`+cardA1+`"}`))
					req = req.WithContext(context.WithValue(req.Context(), ctxKeyReverseIssuerSend, reverseIssuerSend{
						cfg: e.cfg, agent: "agent-one", clientIP: "10.0.0.1", actorAuth: envelope.ActorAuthBound, body: []byte(`{"v":"` + cardA1 + `"}`),
					}))
					e.p.recordIssuerReverseSent(req)
				}
				// Server now reflects cardA1 alongside server-first cardA2.
				e.serveBody("application/json", `{"echo":"`+cardA1+`","siteId":`+cardA2+`}`)
				if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/api/echo"); got != http.StatusOK {
					t.Fatalf("echo status = %d, want 200", got)
				}
				if got := e.do("agent-one", http.MethodGet, target); got != http.StatusForbidden {
					t.Fatalf("%s agent-first reflected 8+8 status = %d, want 403", sendPath, got)
				}
			})
		}
	})

	t.Run("cross-origin subdomain port and trailing-dot halves block", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.serveBody("application/json", `{"a":"`+cardA1+`"}`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/a"); got != http.StatusOK {
			t.Fatalf("origin A status = %d, want 200", got)
		}
		e.serveBody("application/json", `{"b":"`+cardA2+`"}`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOtherHost+"/b"); got != http.StatusOK {
			t.Fatalf("origin B status = %d, want 200", got)
		}
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/join?a="+cardA1+"&b="+cardA2); got != http.StatusForbidden {
			t.Fatalf("cross-origin halves to origin A status = %d, want 403", got)
		}
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOtherHost+"/join?a="+cardA1+"&b="+cardA2); got != http.StatusForbidden {
			t.Fatalf("cross-origin halves to origin B status = %d, want 403", got)
		}

		// Unit-level exact browser origin checks: subdomain, port, trailing dot.
		store := newIssuerQueryStore()
		origin := mustIssuerQueryURL(t, "https://"+numericJoinOriginHost+"/a")
		store.recordSent("sess", origin, nil, nil, true, time.Now())
		store.mintNumericIDs("sess", origin, []string{cardA1, cardA2})
		if !store.numericIDsIssued("sess", mustIssuerQueryURL(t, "https://"+numericJoinOriginHost+":443/b"), []string{cardA1, cardA2}) {
			t.Fatal("default port 443 should match exact browser origin")
		}
		for _, other := range []string{
			"https://" + numericJoinSubdomainHost + "/b",
			"https://" + numericJoinOriginHost + ":8443/b",
			"https://" + numericJoinOriginHost + "./b",
			"http://" + numericJoinOriginHost + "/b",
		} {
			if store.numericIDsIssued("sess", mustIssuerQueryURL(t, other), []string{cardA1, cardA2}) {
				t.Errorf("distinct origin %s reused numeric evidence", other)
			}
		}
	})

	t.Run("server-first provenance on h:443 does not let h:8443 or trailing-dot mint client-introduced value", func(t *testing.T) {
		store := newIssuerQueryStore()
		origin443 := mustIssuerQueryURL(t, "https://"+numericJoinOriginHost+":443/items")
		origin8443 := mustIssuerQueryURL(t, "https://"+numericJoinOriginHost+":8443/items")
		originDot := mustIssuerQueryURL(t, "https://"+numericJoinOriginHost+"./items")

		// 1. h:443 issues cardA1 and cardA2 server-first.
		store.recordSent("sess", origin443, nil, nil, true, time.Now())
		store.mintNumericIDs("sess", origin443, []string{cardA1, cardA2})
		if !store.numericIDsIssued("sess", origin443, []string{cardA1, cardA2}) {
			t.Fatal("h:443 should issue server-first pair")
		}

		// 2. Client sends cardA1 back to h:443 (sets server-first provenance for h:443).
		store.recordSent("sess", mustIssuerQueryURL(t, "https://"+numericJoinOriginHost+":443/use?v="+cardA1), nil, nil, true, time.Now())

		// 3. Client sends cardA1 to h:8443 and h.:443; those origins echo cardA1 alongside cardA2.
		// Neither h:8443 nor h.:443 introduced cardA1, so neither may mint it.
		for _, tc := range []struct {
			name   string
			origin *url.URL
			send   *url.URL
		}{
			{"different port", origin8443, mustIssuerQueryURL(t, "https://"+numericJoinOriginHost+":8443/echo?v="+cardA1)},
			{"trailing dot", originDot, mustIssuerQueryURL(t, "https://"+numericJoinOriginHost+"./echo?v="+cardA1)},
		} {
			store.recordSent("sess", tc.send, nil, nil, true, time.Now())
			store.mintNumericIDs("sess", tc.origin, []string{cardA1, cardA2})
			if store.numericIDsIssued("sess", tc.origin, []string{cardA1, cardA2}) {
				t.Fatalf("%s minted proof for value introduced by client to that origin", tc.name)
			}
		}

		// 4. Same-origin control: h:443 still retains server-first provenance for
		// cardA1 (e.g. after positive generation rollover) and can re-mint it,
		// while h:8443 still cannot.
		next := store.nextGeneration()
		next.mintNumericIDs("sess", origin443, []string{cardA1, cardA2})
		if !next.numericIDsIssued("sess", origin443, []string{cardA1, cardA2}) {
			t.Fatal("h:443 should still qualify to re-mint its own server-first value")
		}
		next.mintNumericIDs("sess", origin8443, []string{cardA1, cardA2})
		if next.numericIDsIssued("sess", origin8443, []string{cardA1, cardA2}) {
			t.Fatal("h:8443 must not mint value after generation rollover")
		}

		// 5. Conservative host-level send history: client sends cardB1 to h:8443
		// first; h:443 echoing cardB1 must stay blocked.
		store2 := newIssuerQueryStore()
		store2.recordSent("sess", mustIssuerQueryURL(t, "https://"+numericJoinOriginHost+":8443/seed?v="+cardB1), nil, nil, true, time.Now())
		store2.mintNumericIDs("sess", origin443, []string{cardB1, cardB2})
		if store2.numericIDsIssued("sess", origin443, []string{cardB1, cardB2}) {
			t.Fatal("h:443 minted value sent agent-first to h:8443 on same host")
		}
	})

	t.Run("after >256 per-origin eviction and >256 per-response cap blocks", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		// Mint cardA1 first.
		e.serveBody("application/json", `{"a":"`+cardA1+`"}`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/first"); got != http.StatusOK {
			t.Fatalf("first mint status = %d, want 200", got)
		}
		// Flood 256 newer distinct 8-digit values across two responses (128 each)
		// plus cardA2, evicting cardA1 from the 256-per-origin LRU.
		for batch := range 2 {
			var nums []string
			for i := range 128 {
				nums = append(nums, fmt.Sprintf(`"%08d"`, 70000000+batch*128+i))
			}
			if batch == 1 {
				nums[len(nums)-1] = `"` + cardA2 + `"`
			}
			e.serveBody("application/json", `{"ids":[`+strings.Join(nums, ",")+`]}`)
			if got := e.do("agent-one", http.MethodGet, fmt.Sprintf("https://%s/flood/%d", numericJoinOriginHost, batch)); got != http.StatusOK {
				t.Fatalf("flood %d status = %d, want 200", batch, got)
			}
		}
		// One extra value pushes cardA1 past 256 active entries.
		e.serveBody("application/json", `{"extra":"79999999"}`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/evict"); got != http.StatusOK {
			t.Fatalf("evict status = %d, want 200", got)
		}
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/detail?a="+cardA1+"&b="+cardA2); got != http.StatusForbidden {
			t.Fatalf("after >256 per-origin eviction status = %d, want 403", got)
		}

		// Per-response cap: 257th distinct number in a single HTML response is not minted.
		e2 := newSameOriginEnv(t, nil)
		var body strings.Builder
		body.WriteString(`<!doctype html><html><body>`)
		for i := range issuerNumericIDMaxPerResponse {
			fmt.Fprintf(&body, " %08d", 80000000+i)
		}
		fmt.Fprintf(&body, " %s %s</body></html>", cardA1, cardA2)
		e2.serveBody("text/html; charset=utf-8", body.String())
		if got := e2.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/cap"); got != http.StatusOK {
			t.Fatalf("cap page status = %d, want 200", got)
		}
		if got := e2.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/detail?a="+cardA1+"&b="+cardA2); got != http.StatusForbidden {
			t.Fatalf("past 256 per-response cap status = %d, want 403", got)
		}
	})

	t.Run("issued pair plus unissued split card or other secret in same query blocks", func(t *testing.T) {
		secret := strings.Join([]string{"Zq8", "Lr2", "Vx9", "Pm4", "Tn7", "Kw3", "Hs6"}, "")
		t.Setenv("PIPELOCK_NUMERIC_JOIN_TEST_SECRET", secret)
		e := newSameOriginEnv(t, func(c *config.Config) {
			configureBrowserCanary(c)
			c.DLP.ScanEnv = true
		})
		e.serveBody("application/json", `{"a":"`+cardA1+`","b":"`+cardA2+`"}`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/seed"); got != http.StatusOK {
			t.Fatalf("seed status = %d, want 200", got)
		}
		// Control: issued pair alone passes.
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/detail?a="+cardA1+"&b="+cardA2); got != http.StatusOK {
			t.Fatalf("control issued pair status = %d, want 200", got)
		}
		for _, tc := range []struct {
			name string
			q    string
		}{
			{"unissued split card in query_concat", "a=" + cardA1 + "&b=" + cardA2 + "&sep=,&c=" + cardB1 + "&d=" + cardB2},
			{"unissued split card in query_subsequence", "a=" + cardA1 + "&b=" + cardA2 + "&c=" + cardB1 + "&d=" + cardB2},
			{"canary token", "a=" + cardA1 + "&b=" + cardA2 + "&ref=" + browserCanaryFixture},
			{"env secret", "a=" + cardA1 + "&b=" + cardA2 + "&ref=" + secret},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/detail?"+tc.q); got != http.StatusForbidden {
					t.Fatalf("%s status = %d, want 403", tc.name, got)
				}
			})
		}
	})

	t.Run("path seam decoded views IBAN and single-value card block", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		ibanA := "GB29" + "NWBK"
		ibanB := "6016" + "1331" + "926819"
		e.serveBody("application/json", `{"a":"`+cardA1+`","b":"`+cardA2+`","i1":"`+ibanA+`","i2":"`+ibanB+`"}`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/seed"); got != http.StatusOK {
			t.Fatalf("seed status = %d, want 200", got)
		}
		fullCard := cardA1 + cardA2
		b64 := base64.StdEncoding.EncodeToString([]byte(fullCard))
		hexCard := hex.EncodeToString([]byte(fullCard))
		for _, tc := range []struct {
			name string
			url  string
		}{
			{"path seam", "https://" + numericJoinOriginHost + "/" + cardA1 + "?site=" + cardA2},
			{"percent-encoded digit", "https://" + numericJoinOriginHost + "/detail?a=%34" + cardA1[1:] + "&b=" + cardA2},
			{"base64 split", "https://" + numericJoinOriginHost + "/detail?a=" + b64[:12] + "&b=" + b64[12:]},
			{"hex split", "https://" + numericJoinOriginHost + "/detail?a=" + hexCard[:16] + "&b=" + hexCard[16:]},
			{"noise-stripped separator", "https://" + numericJoinOriginHost + "/detail?a=" + cardA1 + "&sep=-&b=" + cardA2},
			{"semicolon query", "https://" + numericJoinOriginHost + "/detail?a=" + cardA1 + "&b=" + cardA2 + "&c=1;2"},
			{"single-value card", "https://" + numericJoinOriginHost + "/detail?a=" + fullCard + "&b=1"},
			{"IBAN", "https://" + numericJoinOriginHost + "/detail?a=" + ibanA + "&b=" + ibanB},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := e.do("agent-one", http.MethodGet, tc.url); got != http.StatusForbidden {
					t.Fatalf("%s status = %d, want 403", tc.name, got)
				}
			})
		}
	})

	t.Run("untrusted identity buckets get no relief and cannot poison trusted history", func(t *testing.T) {
		e := newSameOriginEnv(t, func(c *config.Config) {
			c.DefaultAgentIdentity = "agent-one"
		})
		// Untrusted callers send cardA1 first and visit page serving cardA1+cardA2.
		for _, auth := range []envelope.ActorAuth{envelope.ActorAuthUnknown, envelope.ActorAuthSelfDeclared, envelope.ActorAuthMatched} {
			e.serveBody("application/json", `{"a":"`+cardA1+`","b":"`+cardA2+`"}`)
			if got := e.doWithAuth("https://"+numericJoinOriginHost+"/seed?q="+cardA1, auth, nil); got != http.StatusOK {
				t.Fatalf("untrusted %s seed status = %d, want 200", auth, got)
			}
			if got := e.doWithAuth("https://"+numericJoinOriginHost+"/detail?a="+cardA1+"&b="+cardA2, auth, nil); got != http.StatusForbidden {
				t.Fatalf("untrusted %s relief status = %d, want 403", auth, got)
			}
		}
		// Trusted caller was NOT poisoned by untrusted caller's send of cardA1.
		e.serveBody("application/json", `{"a":"`+cardA1+`","b":"`+cardA2+`"}`)
		if got := e.doWithAuth("https://"+numericJoinOriginHost+"/seed", envelope.ActorAuthConfigDefault, nil); got != http.StatusOK {
			t.Fatalf("trusted seed status = %d, want 200", got)
		}
		if got := e.doWithAuth("https://"+numericJoinOriginHost+"/detail?a="+cardA1+"&b="+cardA2, envelope.ActorAuthConfigDefault, nil); got != http.StatusOK {
			t.Fatalf("trusted caller after untrusted send status = %d, want 200", got)
		}
	})

	t.Run("identity change revokes open tunnel and reload preserves or resets appropriately", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		pinned := e.p.issuerCookieRuntime.Load()
		e.serveBody("application/json", `{"a":"`+cardA1+`","b":"`+cardA2+`"}`)
		if got := e.doWithAuth("https://"+numericJoinOriginHost+"/seed", envelope.ActorAuthBound, pinned); got != http.StatusOK {
			t.Fatalf("seed status = %d, want 200", got)
		}
		nav := "https://" + numericJoinOriginHost + "/detail?a=" + cardA1 + "&b=" + cardA2
		if got := e.doWithAuth(nav, envelope.ActorAuthBound, pinned); got != http.StatusOK {
			t.Fatalf("initial status = %d, want 200", got)
		}

		// Unrelated reload preserves evidence on open tunnel.
		unrelated := e.cfg.Clone()
		unrelated.FetchProxy.Monitoring.MaxReqPerMinute++
		e.reload(unrelated)
		if got := e.doWithAuth(nav, envelope.ActorAuthBound, pinned); got != http.StatusOK {
			t.Fatalf("after unrelated reload status = %d, want 200", got)
		}

		// Identity change revokes the previously open tunnel.
		idChanged := e.cfg.Clone()
		idChanged.DefaultAgentIdentity = "reloaded-default"
		e.reload(idChanged)
		if got := e.doWithAuth(nav, envelope.ActorAuthBound, pinned); got != http.StatusForbidden {
			t.Fatalf("stale tunnel after identity change status = %d, want 403", got)
		}

		// Disabling prerequisite revokes evidence; re-enabling starts fresh while keeping agent-first sent history.
		e.serveBody("text/html; charset=utf-8", `<p>ok</p>`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/send?v="+cardB1); got != http.StatusOK {
			t.Fatalf("send cardB1 status = %d, want 200", got)
		}
		off := e.cfg.Clone()
		off.RequestBodyScanning.IssuerBoundSessionCookies = false
		e.reload(off)
		if got := e.do("agent-one", http.MethodGet, nav); got != http.StatusForbidden {
			t.Fatalf("after disable status = %d, want 403", got)
		}
		on := off.Clone()
		on.RequestBodyScanning.IssuerBoundSessionCookies = true
		e.reload(on)
		if got := e.do("agent-one", http.MethodGet, nav); got != http.StatusForbidden {
			t.Fatalf("after re-enable before re-serve status = %d, want 403", got)
		}
		// Server reflects agent-first cardB1 after re-enable: must stay blocked!
		e.serveBody("application/json", `{"b1":"`+cardB1+`","b2":"`+cardB2+`"}`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/reseed"); got != http.StatusOK {
			t.Fatalf("reseed status = %d, want 200", got)
		}
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/detail?a="+cardB1+"&b="+cardB2); got != http.StatusForbidden {
			t.Fatalf("agent-first cardB1 after disable/re-enable status = %d, want 403", got)
		}
	})
}

func TestIssuerNumericLedgerIsolationAndEdgeCases(t *testing.T) {
	cardA1, cardA2 := numericJoinCard16A()
	origin := mustIssuerQueryURL(t, "https://"+numericJoinOriginHost+"/items")

	t.Run("missing or frozen numeric history fails closed", func(t *testing.T) {
		store := newIssuerQueryStore()
		// Missing sent history: mint must fail closed.
		store.mintNumericIDs("sess", origin, []string{cardA1, cardA2})
		if store.numericIDsIssued("sess", origin, []string{cardA1, cardA2}) {
			t.Fatal("mint succeeded without sent history")
		}
		// Unread body freezes numeric history.
		store.recordSent("sess", origin, nil, nil, false, time.Now())
		store.mintNumericIDs("sess", origin, []string{cardA1, cardA2})
		if store.numericIDsIssued("sess", origin, []string{cardA1, cardA2}) {
			t.Fatal("mint succeeded after unread body freeze")
		}
		// Stream freeze (WebSocket / CONNECT passthrough) freezes numeric history.
		store2 := newIssuerQueryStore()
		store2.recordSent("sess", origin, nil, nil, true, time.Now())
		store2.freezeNumericStream("sess", origin)
		store2.mintNumericIDs("sess", origin, []string{cardA1, cardA2})
		if store2.numericIDsIssued("sess", origin, []string{cardA1, cardA2}) {
			t.Fatal("mint succeeded after stream freeze")
		}
	})

	t.Run("JSON number outside float64 range before escaped string still records sent history", func(t *testing.T) {
		store := newIssuerQueryStore()
		escapedNum := fmt.Sprintf(`\u%04x%s`, cardA1[0], cardA1[1:])
		escapedID := fmt.Sprintf(`\u%04x%s`, serverIDListed[0], serverIDListed[1:])
		body := []byte(`{"big":1e400,"num":"` + escapedNum + `","id":"` + escapedID + `"}`)
		store.recordSent("sess", origin, nil, body, true, time.Now())

		// Neither the escaped numeric ID nor the escaped server ID may be
		// minted after the client sent them following 1e400.
		store.mintNumericIDs("sess", origin, []string{cardA1, cardA2})
		if store.numericIDsIssued("sess", origin, []string{cardA1, cardA2}) {
			t.Fatal("numeric value after 1e400 escaped string was minted as server-issued")
		}
		store.mintServerID("sess", origin, serverIDListed, time.Now())
		if store.serverIDIssued("sess", origin, serverIDListed) {
			t.Fatal("server ID after 1e400 escaped string was minted as server-issued")
		}
		// Control: an unsent pair on the same destination still mints (history
		// remained complete because UseNumber decoded 1e400 without error).
		cardB1, cardB2 := numericJoinCard16B()
		store.mintNumericIDs("sess", origin, []string{cardB1, cardB2})
		if !store.numericIDsIssued("sess", origin, []string{cardB1, cardB2}) {
			t.Fatal("unrelated server-first numeric pair failed to mint after 1e400 request")
		}
		// Non-EOF token decode error fails closed (marks history incomplete).
		if _, ok := appendJSONStringsFromDecoder(nil, json.NewDecoder(strings.NewReader(`{"broken":]`))); ok {
			t.Fatal("expected non-EOF JSON decoder error to return ok=false")
		}
	})

	t.Run("client-sent NDJSON and number-literal values never mint", func(t *testing.T) {
		escapedNum := fmt.Sprintf(`\u%04x%s`, cardA1[0], cardA1[1:])
		exponent := cardA1[:1] + "." + cardA1[1:] + "e" + fmt.Sprint(len(cardA1)-1)
		for _, tc := range []struct{ name, body string }{
			{"NDJSON escaped digits", `{"a":"x"}` + "\n" + `{"v":"` + escapedNum + `"}` + "\n"},
			{"exponent whole number", `{"v":` + exponent + `}`},
			{"NDJSON exponent whole number", `{"a":1}` + "\n" + `{"v":` + exponent + `}`},
			{"zero-padded significand with large negative exponent", `{"v":` + cardA1 + strings.Repeat("0", 65) + `e-65}`},
			{"million-zero significand with million negative exponent", `{"v":` + cardA1 + strings.Repeat("0", 1_000_000) + `e-1000000}`},
			{"fraction-spelled whole number", `{"v":` + cardA1 + `.000}`},
			{"undecodable text with escaped digits", `note=[{"v":"` + escapedNum + `"`},
			{"NDJSON exponent before a broken record", `{"v":` + exponent + `}` + "\n" + `{"broken":]`},
			{"undecodable text with exponent literal", `v=` + exponent},
		} {
			t.Run(tc.name, func(t *testing.T) {
				store := newIssuerQueryStore()
				store.recordSent("sess", origin, nil, []byte(tc.body), true, time.Now())
				store.mintNumericIDs("sess", origin, []string{cardA1, cardA2})
				if store.numericIDsIssued("sess", origin, []string{cardA1, cardA2}) {
					t.Fatalf("client-sent value in %q was minted as server-issued", tc.body)
				}
			})
		}
		// Control: plain text with versions and IPs keeps history complete, and
		// a fractional number records no digits, so an unsent pair still mints.
		store := newIssuerQueryStore()
		store.recordSent("sess", origin, nil, []byte(`v=1.2.3&ip=10.0.0.1&id=2c712604-1370-44e7-a1f5-0123456789ab&h=00e1&n=1e5&f={"x":12.5}`), true, time.Now())
		store.mintNumericIDs("sess", origin, []string{cardA1, cardA2})
		if !store.numericIDsIssued("sess", origin, []string{cardA1, cardA2}) {
			t.Fatal("unsent server-first pair failed to mint after a plain form body")
		}
	})

	t.Run("JSON whole-number digits", func(t *testing.T) {
		for _, tc := range []struct {
			in, want string
			ok       bool
		}{
			{"41111111", "41111111", true},
			{"-41111111", "41111111", true},
			{"4.1111111e7", "41111111", true},
			{"4.1111111E+7", "41111111", true},
			{"41111111.000", "41111111", true},
			{"411111110e-1", "41111111", true},
			{"4.11111115e7", "", false},
			{"12.5", "", false},
			{"0." + strings.Repeat("0", 60) + "41111111e68", "41111111", true},
			{"41111111" + strings.Repeat("0", 60) + "e-60", "41111111", true},
			{"0", "0", true},
			{"0.0e5", "0", true},
			{"1e400", "", false},
			{"1e-400", "", false},
			{"1e9999999", "", false},
			{"41111111" + strings.Repeat("0", 1_000_000) + "e-1000000", "41111111", true},
			{"1e1000000000000000000", "", false},
			{"4.1111111e0000007", "41111111", true},
			{"41111111" + strings.Repeat("0", 65) + "e-65", "41111111", true},
			{"41111111" + strings.Repeat("0", 900) + "e-900", "41111111", true},
			{"4.1111111E+00000007", "41111111", true},
			{"411111110e-00000001", "41111111", true},
			{"1" + strings.Repeat("0", 70), "", false},
		} {
			got, ok := jsonWholeNumberDigits(tc.in)
			if got != tc.want || ok != tc.ok {
				t.Errorf("jsonWholeNumberDigits(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
			}
		}
	})

	t.Run("separate numeric budget never freezes server_issued_id learning", func(t *testing.T) {
		store := newIssuerQueryStore()
		// Overflow numeric per-request token limit (>4096 8-digit numbers, each < 16 chars so server_issued_id sees 0 tokens).
		var numericFlood strings.Builder
		for i := range issuerNumericSentMaxTokensPerRequest + 10 {
			fmt.Fprintf(&numericFlood, "%08d ", 60000000+i)
		}
		store.recordSent("sess", origin, nil, []byte(numericFlood.String()), true, time.Now())
		// Numeric learning for this destination is frozen.
		store.mintNumericIDs("sess", origin, []string{cardA1, cardA2})
		if store.numericIDsIssued("sess", origin, []string{cardA1, cardA2}) {
			t.Fatal("numeric destination should be frozen after numeric token overflow")
		}
		// server_issued_id learning on the exact same destination MUST still work!
		store.mintServerID("sess", origin, serverIDListed, time.Now())
		if !store.serverIDIssued("sess", origin, serverIDListed) {
			t.Fatal("numeric ledger overflow froze server_issued_id learning")
		}
	})

	t.Run("HTML truncation boundary never slices >14 digit run and JSON keys never mint", func(t *testing.T) {
		// Construct a 16-digit card straddling the 4 MiB HTML boundary.
		fullCard := cardA1 + cardA2
		prefix := strings.Repeat("x", issuerQueryMaxHTMLBytes-10)
		html := []byte(prefix + fullCard + "tail")
		ids := extractHTMLNumericIDs(html, issuerNumericIDMaxPerResponse)
		if len(ids) != 0 {
			t.Fatalf("16-digit run straddling 4 MiB boundary was sliced into %v", ids)
		}
		// JSON object key must not mint.
		e := newSameOriginEnv(t, nil)
		e.serveBody("application/json", `{"`+cardA1+`":"ok","`+cardA2+`":"ok"}`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/keys"); got != http.StatusOK {
			t.Fatalf("keys status = %d, want 200", got)
		}
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/detail?a="+cardA1+"&b="+cardA2); got != http.StatusForbidden {
			t.Fatalf("JSON object keys should not mint, got %d", got)
		}
		// Non-ASCII-transparent XHTML must not mint.
		e.serveBody("application/xhtml+xml", `<html><body>`+cardA1+` `+cardA2+`</body></html>`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/xhtml"); got != http.StatusOK {
			t.Fatalf("xhtml status = %d, want 200", got)
		}
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/detail?a="+cardA1+"&b="+cardA2); got != http.StatusForbidden {
			t.Fatalf("application/xhtml+xml should not mint, got %d", got)
		}
	})

	t.Run("concurrent recordSent mint and lookup are race-free", func(t *testing.T) {
		store := newIssuerQueryStore()
		store.recordSent("sess", origin, nil, nil, true, time.Now())
		var wg sync.WaitGroup
		for i := range 4 {
			wg.Go(func() {
				for j := range 50 {
					v1 := fmt.Sprintf("%08d", 91000000+i*100+j)
					v2 := fmt.Sprintf("%08d", 92000000+i*100+j)
					store.mintNumericIDs("sess", origin, []string{v1, v2})
					_ = store.numericIDsIssued("sess", origin, []string{v1, v2})
					store.recordSent("sess", origin, nil, []byte(v1+" "+v2), true, time.Now())
				}
			})
		}
		wg.Wait()
	})
}

func TestIssuerNumericCardJoin_DefaultsMatrix(t *testing.T) {
	woID, siteID := numericJoinRealShape19()
	navURL := "https://" + numericJoinOriginHost + "/records/detail?wo=" + woID + "&site=" + siteID

	loadFromYAML := func(t *testing.T, fieldYAML string) *config.Config {
		t.Helper()
		// Only the issuer field is read from this config; omit TLS interception
		// so loading does not depend on a CA in the runner's home directory.
		raw := "mode: balanced\nrequest_body_scanning:\n  enabled: true\n  scan_headers: true\n"
		if fieldYAML != "" {
			raw += "  " + fieldYAML + "\n"
		}
		cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
		if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("config.Load(%q): %v", fieldYAML, err)
		}
		return cfg
	}

	for _, tc := range []struct {
		name       string
		fieldYAML  string
		wantStatus int
	}{
		{"omitted", "", http.StatusOK},
		{"yaml null", "issuer_bound_session_cookies: null", http.StatusOK},
		{"yaml blank", "issuer_bound_session_cookies:", http.StatusOK},
		{"explicit false", "issuer_bound_session_cookies: false", http.StatusForbidden},
		{"explicit true", "issuer_bound_session_cookies: true", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loaded := loadFromYAML(t, tc.fieldYAML)
			e := newSameOriginEnv(t, func(c *config.Config) {
				c.RequestBodyScanning.IssuerBoundSessionCookies = loaded.RequestBodyScanning.IssuerBoundSessionCookies
			})
			e.serveBody("text/html; charset=utf-8", `<p>`+woID+`</p>`)
			if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/list"); got != http.StatusOK {
				t.Fatalf("list status = %d, want 200", got)
			}
			e.serveBody("application/json", `{"siteId":`+siteID+`}`)
			if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/sites"); got != http.StatusOK {
				t.Fatalf("sites status = %d, want 200", got)
			}
			if got := e.do("agent-one", http.MethodGet, navURL); got != tc.wantStatus {
				t.Fatalf("nav status = %d, want %d", got, tc.wantStatus)
			}
		})
	}

	t.Run("reload without change keeps relief and reload with change revokes relief", func(t *testing.T) {
		loadedOn := loadFromYAML(t, "")
		loadedOff := loadFromYAML(t, "issuer_bound_session_cookies: false")
		e := newSameOriginEnv(t, func(c *config.Config) {
			c.RequestBodyScanning.IssuerBoundSessionCookies = loadedOn.RequestBodyScanning.IssuerBoundSessionCookies
		})
		e.serveBody("text/html; charset=utf-8", `<p>`+woID+`</p>`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/list"); got != http.StatusOK {
			t.Fatalf("list status = %d, want 200", got)
		}
		e.serveBody("application/json", `{"siteId":`+siteID+`}`)
		if got := e.do("agent-one", http.MethodGet, "https://"+numericJoinOriginHost+"/sites"); got != http.StatusOK {
			t.Fatalf("sites status = %d, want 200", got)
		}
		if got := e.do("agent-one", http.MethodGet, navURL); got != http.StatusOK {
			t.Fatalf("initial status = %d, want 200", got)
		}

		noChange := e.cfg.Clone()
		noChange.RequestBodyScanning.IssuerBoundSessionCookies = loadedOn.RequestBodyScanning.IssuerBoundSessionCookies
		noChange.FetchProxy.Monitoring.MaxReqPerMinute++
		e.reload(noChange)
		if got := e.do("agent-one", http.MethodGet, navURL); got != http.StatusOK {
			t.Fatalf("reload without change status = %d, want 200", got)
		}

		withChange := e.cfg.Clone()
		withChange.RequestBodyScanning.IssuerBoundSessionCookies = loadedOff.RequestBodyScanning.IssuerBoundSessionCookies
		e.reload(withChange)
		if got := e.do("agent-one", http.MethodGet, navURL); got != http.StatusForbidden {
			t.Fatalf("reload with change status = %d, want 403", got)
		}
	})
}

// numericJoinDoWithReason sends one intercepted request and returns its status
// with the X-Pipelock-Block-Reason header, so a test can tell a receipt failure
// from an ordinary DLP refusal.
func numericJoinDoWithReason(e *delegationEnv, agent, rawURL string) (int, string) {
	e.t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		e.t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	resp := interceptAndRequestWithRecorder(e.t, interceptRequestOptions{
		Upstream: e.upstream, TargetHost: u.Hostname(), TargetPort: "443", UpstreamRT: e.rt,
		Cache: e.cache, Pool: e.pool, Config: e.cfg, Scanner: e.sc, Logger: e.logger, Metrics: e.m,
		Request: req, Proxy: e.p, Agent: agent, ActorAuth: envelope.ActorAuthBound,
	})
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("X-Pipelock-Block-Reason")
}

func TestInterceptIssuerNumericCardJoinRevokedBeforeSend(t *testing.T) {
	woID, siteID := numericJoinRealShape19()
	e := newSameOriginEnv(t, func(c *config.Config) {
		c.RequestBodyScanning.Enabled = true
		c.Taint.Policy = config.ModePermissive
	})
	logs, _ := e.withRecordedAudit(t)
	origin := "https://" + numericJoinOriginHost
	e.serveBody("text/html; charset=utf-8", `<p>`+woID+`</p>`)
	if got := e.do("agent-one", http.MethodGet, origin+"/records/list"); got != http.StatusOK {
		t.Fatalf("HTML status = %d, want 200", got)
	}
	e.serveBody("application/json", `{"siteId":`+siteID+`}`)
	if got := e.do("agent-one", http.MethodGet, origin+"/api/sites"); got != http.StatusOK {
		t.Fatalf("JSON status = %d, want 200", got)
	}
	hitsBefore := e.sourceHit.Load()

	bodyReader, bodyWriter := io.Pipe()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, origin+"/records/detail?wo="+woID+"&site="+siteID, bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	status := make(chan int, 1)
	cfg, sc, logger, p := e.cfg, e.sc, e.logger, e.p
	go func() {
		resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
			Upstream: e.upstream, TargetHost: numericJoinOriginHost, TargetPort: "443", UpstreamRT: e.rt,
			Cache: e.cache, Pool: e.pool, Config: cfg, Scanner: sc, Logger: logger, Metrics: e.m,
			Request: req, Proxy: p, Agent: "agent-one", ActorAuth: envelope.ActorAuthBound,
		})
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		status <- resp.StatusCode
	}()
	// The relief is recorded right after the URL rescan, before the body is
	// read, so its audit event marks the window to reload in.
	testwait.For(t, 10*time.Second, func() bool {
		return strings.Contains(logs.String(), `"event":"dlp_issuer_numeric_card_join_allow"`)
	}, "numeric card-join relief was never recorded")
	disabled := cfg.Clone()
	disabled.RequestBodyScanning.IssuerBoundSessionCookies = false
	e.reload(disabled)
	_, _ = io.WriteString(bodyWriter, "note=ready")
	_ = bodyWriter.Close()

	if got := <-status; got != http.StatusForbidden {
		t.Fatalf("revoked numeric relief status = %d, want 403; audit: %s", got, logs.String())
	}
	if got := e.sourceHit.Load(); got != hitsBefore {
		t.Fatalf("revoked numeric relief reached the upstream (%d hits, want %d)", got, hitsBefore)
	}
	if !strings.Contains(logs.String(), issuerNumericCardJoinStaleLayer) {
		t.Fatalf("stale numeric relief refusal not logged; audit: %s", logs.String())
	}
}
