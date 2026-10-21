// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
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

// escapedAgentBlob is agentBlob with its first character written as a JSON
// unicode escape. The escape is capital K (U+004B); a lowercase escape decodes
// to a different string and cannot stand in for this value.
func escapedAgentBlob() string {
	return string([]byte{0x5c}) + "u004B" + agentBlob[1:]
}

func decodedEscapedAgentBlob() string {
	return "K" + agentBlob[1:]
}

func newSentIssuerProxy(t *testing.T) (*Proxy, *config.Config) {
	t.Helper()
	cfg := config.Defaults()
	cfg.TLSInterception.Enabled = true
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p, cfg
}

func TestIssuerSentUntrustedInterceptCannotMintAcrossSessions(t *testing.T) {
	for _, auth := range []envelope.ActorAuth{
		envelope.ActorAuthBound, envelope.ActorAuthUnknown, envelope.ActorAuthSelfDeclared,
	} {
		t.Run(string(auth), func(t *testing.T) {
			p, cfg := newSentIssuerProxy(t)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/filters", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Criteria", agentBlob)
			ic := &InterceptContext{Proxy: p, Config: cfg, ClientIP: "127.0.0.1", Agent: "sender", ActorAuth: auth}
			recordIssuerRequestSent(ic, req, nil)
			store := p.issuerStoreForUnmediatedSend()
			recipient := sessionKeyFor(cfg, "recipient", "127.0.0.1", envelope.ActorAuthBound)
			store.mintServerID(recipient, req.URL, agentBlob, time.Now())
			if store.serverIDIssued(recipient, req.URL, agentBlob) {
				t.Fatal("a value sent through interception minted as another session's server-issued ID")
			}
			control := "Z" + agentBlob[1:]
			store.mintServerID(recipient, req.URL, control, time.Now())
			if !store.serverIDIssued(recipient, req.URL, control) {
				t.Fatal("an unsent value did not mint for the same recipient and origin")
			}
		})
	}
}

func TestInterceptUntrustedReflectionCannotIssueID(t *testing.T) {
	h := newWebPlatformHarness(t)
	var mu sync.Mutex
	var supplied string
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/submit" {
			supplied = r.Header.Get("X-Criteria")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"value":[{"id":"`+supplied+`"},{"id":"`+serverIDOther+`"}]}`)
	}))
	t.Cleanup(api.Close)
	do := func(path, value string, auth envelope.ActorAuth) int {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, api.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if value != "" {
			req.Header.Set("X-Criteria", value)
		}
		resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
			Upstream: api, Cache: h.cache, Pool: h.pool, Config: h.cfg, Scanner: h.sc,
			Logger: h.logger, Metrics: h.m, Request: req, Proxy: h.p,
			Agent: "recipient", ActorAuth: auth,
		})
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if got := do("/submit", agentBlob, envelope.ActorAuthUnknown); got != http.StatusNoContent {
		t.Fatalf("untrusted sender = %d, want 204", got)
	}
	if got := do("/filters", "", envelope.ActorAuthBound); got != http.StatusOK {
		t.Fatalf("trusted recipient listing = %d, want 200", got)
	}
	if got := do("/filters/"+agentBlob, "", envelope.ActorAuthBound); got != http.StatusForbidden {
		t.Fatalf("reflected ID = %d, want 403", got)
	}
	if got := do("/filters/"+serverIDOther, "", envelope.ActorAuthBound); got != http.StatusOK {
		t.Fatalf("unsent listed ID = %d, want 200", got)
	}
}

func TestIssuerSentIncompleteAcrossSessions(t *testing.T) {
	origin, err := url.Parse("https://api.vendor.example/filters")
	if err != nil {
		t.Fatal(err)
	}
	other, err := url.Parse("https://other.vendor.example/filters")
	if err != nil {
		t.Fatal(err)
	}
	for _, cause := range []string{"unread body", "unread http", "unread other port", "request limit", "session limit", "websocket"} {
		t.Run(cause, func(t *testing.T) {
			p, cfg := newSentIssuerProxy(t)
			s := p.issuerStoreForUnmediatedSend()
			now := time.Now()
			recipient := sessionKeyFor(cfg, "recipient", "127.0.0.1", envelope.ActorAuthUnknown)
			s.mintServerID(recipient, origin, serverIDListed, now)
			if !s.serverIDIssued(recipient, origin, serverIDListed) {
				t.Fatal("positive control: recipient did not learn the ID")
			}
			var body []byte
			known := true
			target := *origin
			switch cause {
			case "unread body":
				known = false
			case "unread http":
				known = false
				target.Scheme = "http"
			case "unread other port":
				known = false
				target.Host += ":8443"
			case "request limit":
				body = []byte(strings.Repeat(serverIDOther+" ", issuerSentMaxTokensPerRequest+1))
			case "session limit":
				s.sent["sender"] = make(map[[32]byte]struct{})
				for i := 0; i < issuerSentMaxEntries; i++ {
					var digest [32]byte
					digest[0], digest[1] = byte(i), byte(i>>8)
					s.sent["sender"][digest] = struct{}{}
				}
				body = []byte(serverIDOther + " " + agentBlob)
			}
			if cause == "websocket" {
				target.Scheme = "wss"
				p.taintIssuerSessionForStream(cfg, "sender", "192.0.2.1", envelope.ActorAuthBound, &target)
			} else {
				s.recordSent("sender", &target, nil, body, known, now)
			}
			if s.serverIDIssued(recipient, origin, serverIDListed) {
				t.Fatal("recipient kept an ID after another caller's incomplete send")
			}
			s.mintServerID("fresh-recipient", origin, agentBlob, now)
			if s.serverIDIssued("fresh-recipient", origin, agentBlob) {
				t.Fatal("another caller minted after incomplete send history")
			}
			s.mintServerID(recipient, other, serverIDListed, now)
			if !s.serverIDIssued(recipient, other, serverIDListed) {
				t.Fatal("incomplete history for one host blocked a different host")
			}
		})
	}
}

func TestIssuerSentHostUncertaintyFailsClosed(t *testing.T) {
	origin, err := url.Parse("https://api.vendor.example/filters")
	if err != nil {
		t.Fatal(err)
	}
	for _, cause := range []string{"missing target", "missing host", "history full"} {
		t.Run(cause, func(t *testing.T) {
			s := newTestServerIDStore(t)
			s.mu.Lock()
			switch cause {
			case "missing target":
				s.taintSentHostLocked(nil)
			case "missing host":
				s.taintSentHostLocked(&url.URL{})
			case "history full":
				for i := 0; i < issuerSentAllMaxEntries; i++ {
					var digest [32]byte
					digest[0], digest[1], digest[2] = byte(i), byte(i>>8), byte(i>>16)
					s.sentAll[digest] = struct{}{}
				}
				s.taintSentHostLocked(origin)
			}
			s.mu.Unlock()
			s.mintServerID("recipient", origin, serverIDListed, time.Now())
			if s.serverIDIssued("recipient", origin, serverIDListed) {
				t.Fatal("uncertainty failed open")
			}
		})
	}
}

func TestIssuerSentJSONTextOutsideRawBody(t *testing.T) {
	origin, err := url.Parse("https://api.vendor.example/v1/filters")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	escaped := escapedAgentBlob()
	if decodedEscapedAgentBlob() != agentBlob {
		t.Fatalf("escape fixture decodes to %q, want %q", decodedEscapedAgentBlob(), agentBlob)
	}
	object := `{"query":"` + escaped + `"}`
	query := url.Values{}
	query.Set("criteria", object)
	withQuery, err := url.Parse("https://api.vendor.example/v1/filters?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	form := "criteria=" + url.QueryEscape(object)

	cases := []struct {
		name   string
		target *url.URL
		header http.Header
		body   string
	}{
		{name: "query", target: withQuery},
		{name: "header", target: origin, header: http.Header{"X-Criteria": {object}}},
		{name: "form field", target: origin, body: form},
		{name: "json body", target: origin, body: object},
		{name: "json key", target: origin, body: `{"` + escaped + `":"x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServerIDStore(t)
			target := tc.target
			if target == nil {
				target = origin
			}
			s.recordSent("a", target, tc.header, []byte(tc.body), true, now)
			s.mintServerID("a", origin, agentBlob, now)
			if s.serverIDIssued("a", origin, agentBlob) {
				t.Fatal("JSON-decoded value was minted")
			}
		})
	}
}

func TestIssuerSentUserinfo(t *testing.T) {
	origin, err := url.Parse("https://api.vendor.example/v1/filters")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	withUser, err := url.Parse("https://api.vendor.example/notes/index")
	if err != nil {
		t.Fatal(err)
	}
	withUser.User = url.UserPassword("agent", agentBlob)

	t.Run("store", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.recordSent("a", withUser, nil, nil, true, now)
		s.mintServerID("a", origin, agentBlob, now)
		if s.serverIDIssued("a", origin, agentBlob) {
			t.Fatal("URL userinfo password was minted")
		}
	})

	t.Run("fetch helper", func(t *testing.T) {
		p, cfg := newSentIssuerProxy(t)
		p.recordIssuerFetchSent(cfg, "mail-agent", "127.0.0.1", envelope.ActorAuthBound, withUser)
		store := p.issuerStoreForUnmediatedSend()
		session := sessionKeyFor(cfg, "mail-agent", "127.0.0.1", envelope.ActorAuthBound)
		store.mintServerID(session, origin, agentBlob, now)
		if store.serverIDIssued(session, origin, agentBlob) {
			t.Fatal("a /fetch userinfo password was minted")
		}
	})

	t.Run("client delivers userinfo as basic auth", func(t *testing.T) {
		var user, pass string
		var ok bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok = r.BasicAuth()
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)
		u, err := url.Parse(srv.URL + "/notes/index")
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword("agent", agentBlob)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		if !ok || user != "agent" || pass != agentBlob {
			t.Fatalf("origin saw user=%q pass=%q ok=%v", user, pass, ok)
		}
	})

	t.Run("top-level userinfo is not blocked by the URL scan", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Internal = nil // no DNS; this checks whether userinfo itself is scored
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		result := sc.Scan(context.Background(), "https://agent:"+agentBlob+"@api.vendor.example/notes/index")
		if !result.Allowed {
			t.Fatalf("userinfo URL blocked: %s", result.Reason)
		}
	})
}

func TestIssuerSentStaleTunnel(t *testing.T) {
	p, cfg := newSentIssuerProxy(t)
	pinned := p.issuerCookieRuntime.Load()
	if pinned == nil || pinned.query == nil {
		t.Fatal("positive control: issuer runtime missing")
	}
	ic := &InterceptContext{
		Proxy:         p,
		Config:        cfg,
		Agent:         "mail-agent",
		ClientIP:      "127.0.0.1",
		ActorAuth:     envelope.ActorAuthBound,
		IssuerRuntime: pinned,
	}
	// An enabled reload keeps the query store and publishes a new runtime
	// pointer. Tunnels admitted before the reload keep the old pointer.
	p.issuerCookieRuntime.Store(&issuerCookieRuntime{cfg: cfg, store: pinned.store, query: pinned.query})
	if ic.issuerQueryStore() != nil {
		t.Fatal("positive control: pinned runtime still matches")
	}
	origin, err := url.Parse("https://api.vendor.example/v1/filters")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, origin.String(), strings.NewReader(agentBlob))
	recordIssuerRequestSent(ic, req, []byte(agentBlob))
	session := sessionKeyFor(cfg, ic.Agent, ic.ClientIP, ic.ActorAuth)
	live := p.issuerCookieRuntime.Load().query
	now := time.Now()
	live.mintServerID(session, origin, agentBlob, now)
	if live.serverIDIssued(session, origin, agentBlob) {
		t.Fatal("a value sent on a stale tunnel was minted")
	}
	live.mintServerID(session, origin, serverIDListed, now)
	if !live.serverIDIssued(session, origin, serverIDListed) {
		t.Fatal("stale-tunnel recording tainted the session or blocked a value it did not send")
	}
}

// A tunnel admitted while the feature was off keeps forwarding after a reload
// turns it on. Its sends must reach the live store, or a value it carried
// could later mint as an ID.
func TestIssuerSentTunnelOpenedWhileDisabled(t *testing.T) {
	p, cfg := newSentIssuerProxy(t)
	off := *cfg
	off.RequestBodyScanning.IssuerBoundSessionCookies = false
	if issuerCookieEnabled(&off) {
		t.Fatal("positive control: disabling the setting did not disable the feature")
	}
	ic := &InterceptContext{
		Proxy:     p,
		Config:    &off,
		Agent:     "mail-agent",
		ClientIP:  "127.0.0.1",
		ActorAuth: envelope.ActorAuthBound,
	}
	if ic.issuerQueryStore() != nil {
		t.Fatal("positive control: a tunnel with the feature off saw the store")
	}
	origin, err := url.Parse("https://api.vendor.example/v1/filters")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, origin.String(), strings.NewReader(agentBlob))
	recordIssuerRequestSent(ic, req, []byte(agentBlob))
	session := sessionKeyFor(cfg, ic.Agent, ic.ClientIP, ic.ActorAuth)
	live := p.issuerCookieRuntime.Load().query
	live.mintServerID(session, origin, agentBlob, time.Now())
	if live.serverIDIssued(session, origin, agentBlob) {
		t.Fatal("a value sent on a tunnel opened while the feature was off was minted")
	}
}

func TestIssuerSentMultipartAndChunkedBody(t *testing.T) {
	origin, err := url.Parse("https://api.vendor.example/v1/filters")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s := newTestServerIDStore(t)
	multipart := "--bound\r\nContent-Disposition: form-data; name=\"payload\"\r\n\r\n" + agentBlob + "\r\n--bound--\r\n"
	s.recordSent("a", origin, nil, []byte(multipart), true, now)
	s.mintServerID("a", origin, agentBlob, now)
	if s.serverIDIssued("a", origin, agentBlob) {
		t.Fatal("a multipart field was minted")
	}
}

// A chunked request body (no Content-Length) through the intercept proxy is
// buffered before forwarding, so the value it carries is recorded as sent and
// never mints when the origin lists it back.
func TestInterceptChunkedBodyRecordedAsSent(t *testing.T) {
	h := newWebPlatformHarness(t)
	api, hits := newMailAPI(t)
	const agent = "mail-agent"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, api.URL+"/filters",
		io.MultiReader(strings.NewReader(`{"criteria":{"query":"`), strings.NewReader(agentBlob), strings.NewReader(`"}}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1 // chunked transfer encoding
	resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
		Upstream: api, Cache: h.cache, Pool: h.pool, Config: h.cfg, Scanner: h.sc,
		Logger: h.logger, Metrics: h.m, Request: req, Proxy: h.p,
		Agent: agent, ActorAuth: envelope.ActorAuthBound,
	})
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chunked create = %d", resp.StatusCode)
	}
	if got := h.send(api, http.MethodGet, "/filters", agent, "", ""); got != http.StatusOK {
		t.Fatalf("list = %d", got)
	}
	if got := h.send(api, http.MethodDelete, "/filters/"+agentBlob, agent, "", ""); got != http.StatusForbidden {
		t.Fatalf("chunked-body reflection as id = %d, want 403", got)
	}
	if hits("DELETE /filters/"+agentBlob) != 0 {
		t.Fatal("a value sent in a chunked body reached upstream as an id")
	}
}
