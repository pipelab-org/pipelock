// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// browserKey is shaped like a public browser API key a site ships in its own
// pages. Built at runtime so no credential literal is committed.
func browserKey() string {
	return "AIza" + strings.Repeat("Sy", 10) + "B" + strings.Repeat("x7", 7)
}

const issuedValuePath = "/complete/search"

func issuedValueURL(host, query string) string {
	return "https://" + host + issuedValuePath + "?" + query
}

// serveJSON makes the source origin answer with a JSON document.
func (e *delegationEnv) serveJSON(body string) {
	e.issue(http.StatusOK)
	e.sourcePayload.Store(&struct{ contentType, body string }{"application/json", body})
}

func TestInterceptIssuedValueDLP(t *testing.T) {
	key := browserKey()
	query := "client=web&key=" + key
	target := issuedValueURL(delegationSourceHost, query)

	t.Run("baseline: the key blocks", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		if got := e.do("agent-one", http.MethodGet, target); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: the premise of every other case", got)
		}
	})

	t.Run("a link the origin served passes", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(issuedValuePath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, target); got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
	})

	t.Run("a key the origin served in JSON passes on any path of that origin", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.serveJSON(`{"config":{"apiKey":"` + key + `"}}`)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, "https://"+delegationSourceHost+"/other/endpoint?key="+key); got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
	})

	t.Run("a key the session sent first is not issued by an echo", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		origin, _ := url.Parse("https://" + delegationSourceHost + "/upload")
		store := e.p.issuerCookieRuntime.Load().query
		store.recordSent(sessionKeyFor(e.cfg, "agent-one", "10.0.0.1", envelope.ActorAuthBound), origin, nil, []byte(key), true, time.Now())
		e.serveJSON(`{"echo":"` + key + `"}`)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, "https://"+delegationSourceHost+"/other/endpoint?key="+key); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("another session gets nothing", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(issuedValuePath + "?" + query)
		e.visit()
		if got := e.do("agent-two", http.MethodGet, target); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("another origin gets nothing", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(issuedValuePath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issuedValueURL("elsewhere.vendor.example", query)); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("the same key also in a value without evidence is ambiguous", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage(issuedValuePath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, target+"&copy="+key); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("the same key also in the path is ambiguous", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		e.servePage("/" + key + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, "https://"+delegationSourceHost+"/"+key+"?"+query); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("canary beside an issued key still blocks", func(t *testing.T) {
		e := newSameOriginEnv(t, configureBrowserCanary)
		withCanary := query + "&ref=" + browserCanaryFixture
		e.servePage(issuedValuePath + "?" + withCanary)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issuedValueURL(delegationSourceHost, withCanary)); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("environment secret served by the origin still blocks", func(t *testing.T) {
		secret := strings.Join([]string{"Zq8", "Lr2", "Vx9", "Pm4", "Tn7", "Kw3", "Hs6"}, "")
		t.Setenv("PIPELOCK_ISSUED_VALUE_TEST_SECRET", secret)
		e := newSameOriginEnv(t, func(c *config.Config) { c.DLP.ScanEnv = true })
		withSecret := "client=web&token=" + secret
		e.servePage(issuedValuePath + "?" + withSecret)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issuedValueURL(delegationSourceHost, withSecret)); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("core floor credential served by the origin still blocks", func(t *testing.T) {
		e := newSameOriginEnv(t, nil)
		aws := "client=web&k=" + "AKIA" + "IOSFODNN7" + "EXAMPLE"
		e.servePage(issuedValuePath + "?" + aws)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, issuedValueURL(delegationSourceHost, aws)); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})

	t.Run("disabled issuer evidence gives no relief", func(t *testing.T) {
		e := newSameOriginEnv(t, func(c *config.Config) { c.RequestBodyScanning.IssuerBoundSessionCookies = false })
		e.servePage(issuedValuePath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, target); got != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", got)
		}
	})
}

func TestIssuedValueMatch(t *testing.T) {
	all := func(string, string) bool { return true }
	none := func(string, string) bool { return false }
	only := func(k string) func(string, string) bool { return func(key, _ string) bool { return key == k } }
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	for _, tc := range []struct {
		name, raw, matched string
		issued             func(string, string) bool
		want               bool
	}{
		{"whole issued value", "https://h.example/p?k=SECRET", "SECRET", all, true},
		{"substring of issued value", "https://h.example/p?k=xSECRETy", "SECRET", all, true},
		{"not issued", "https://h.example/p?k=SECRET", "SECRET", none, false},
		{"also in unissued value", "https://h.example/p?k=SECRET&o=SECRET", "SECRET", only("k"), false},
		{"spans two values", "https://h.example/p?a=SEC&b=RET", "SECRET", all, false},
		{"in path", "https://h.example/SECRET?k=SECRET", "SECRET", all, false},
		{"in host", "https://secret.h.example/p?k=secret", "secret", all, false},
		{"in key", "https://h.example/p?SECRET=SECRET", "SECRET", all, false},
		{"unparseable query", "https://h.example/p?k=SECRET;x", "SECRET", all, false},
		{"empty match", "https://h.example/p?k=SECRET", "", all, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := issuedValueMatch(parse(tc.raw), tc.matched, tc.issued); got != tc.want {
				t.Fatalf("issuedValueMatch = %v, want %v", got, tc.want)
			}
		})
	}
	if issuedValueMatch(nil, "x", all) || issuedValueMatch(parse("https://h.example/?k=x"), "x", nil) {
		t.Fatal("nil inputs admitted a match")
	}
}
