// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
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
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

// Synthetic IDs in the shape mail and directory APIs return: long, mixed
// case, base64url with padding. Each scores above the default threshold.
const (
	serverIDListed  = "ANe1BmglugETAHWRiqgwKkow2QrNknpy1yV5Mw"
	serverIDCreated = "AAMkADIzNTA3ZDFlLWYyM2QtNDE3OS1hYTczLTdmMmRhYjFhOWFkMABGAAA="
	serverIDKeyOnly = "Qx7vPq2LmZ9tRw4KbNy8JsHd3FgUcVe6Ta1Mo5"
	serverIDOther   = "Zr8KmWq3NvXp6LbTy2HjDs9FgCuQa4Ve7Ro1Me"
	// agentBlob is the value an agent smuggles: ID-shaped, high entropy.
	agentBlob = "Kd93JqWm2Xv7RbLp4TzNy8HsQf6GcUaE1Vo5Mi"
)

func TestIssuerIDBlockObservation(t *testing.T) {
	var logs bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	p := &Proxy{metrics: metrics.New(), logger: logger}
	s := p.newObservedIssuerQueryStore()
	origin, _ := url.Parse("https://api.vendor.example/items")
	s.freezeIDCallerLocked("first")
	s.freezeIDCallerLocked("first")
	s.freezeIDCallerLocked("second")
	response := httptest.NewRecorder()
	p.metrics.PrometheusHandler().ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if !strings.Contains(response.Body.String(), `pipelock_issuer_id_blocks_total{scope="session"} 2`) {
		t.Fatal("session transition metric missing")
	}
	if strings.Count(logs.String(), "anomaly detected") != 1 || strings.Contains(logs.String(), origin.Host) || strings.Contains(logs.String(), "first") {
		t.Fatalf("expected one coalesced warning without identities or hosts, got %s", logs.String())
	}
	if !strings.Contains(logs.String(), "only a restart resets history") {
		t.Fatal("warning omitted recovery guidance")
	}
	fresh := p.newObservedIssuerQueryStore()
	fresh.recordSent("first", origin, nil, nil, true, time.Now())
	if fresh.mintBlockedLocked("first", origin) || fresh.idBlockReported {
		t.Fatal("fresh store retained uncertainty or log coalescing")
	}
	plain := (&Proxy{}).newObservedIssuerQueryStore()
	plain.freezeIDCallerLocked("first")
}

func (h *webPlatformHarness) send(upstream *httptest.Server, method, path, agent, contentType, body string) int {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, upstream.URL+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp := interceptAndRequestWithRecorder(h.t, interceptRequestOptions{
		Upstream: upstream, Cache: h.cache, Pool: h.pool, Config: h.cfg, Scanner: h.sc,
		Logger: h.logger, Metrics: h.m, Request: req, Proxy: h.p,
		Agent: agent, ActorAuth: envelope.ActorAuthBound,
	})
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func (h *webPlatformHarness) sendHeader(upstream *httptest.Server, method, path, agent, name, value, body string) int {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, upstream.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(name, value)
	resp := interceptAndRequestWithRecorder(h.t, interceptRequestOptions{
		Upstream: upstream, Cache: h.cache, Pool: h.pool, Config: h.cfg, Scanner: h.sc,
		Logger: h.logger, Metrics: h.m, Request: req, Proxy: h.p,
		Agent: agent, ActorAuth: envelope.ActorAuthBound,
	})
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// api2Store makes the mail API store value out of band, standing in for an
// origin that kept what the agent sent in a header or form field and now
// lists it, then has the agent list the collection.
func api2Store(t *testing.T, h *webPlatformHarness, agent string, api *httptest.Server, value string) {
	t.Helper()
	// Straight to the server, not through the proxy, so the only record of
	// the value being sent is the request under test.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, api.URL+"/filters", strings.NewReader(`{"criteria":{"query":"`+value+`"}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := api.Client().Do(req)
	if err != nil {
		t.Fatalf("out-of-band store: %v", err)
	}
	_ = resp.Body.Close()
	if got := h.send(api, http.MethodGet, "/filters", agent, "", ""); got != http.StatusOK {
		t.Fatalf("list = %d", got)
	}
}

// newMailAPI serves a filter collection: list, create (which stores and later
// lists whatever criteria the agent sent), and delete by ID. Every request
// that reaches it is counted per path, so a test can tell forwarded from
// blocked.
func newMailAPI(t *testing.T) (*httptest.Server, func(string) int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	var stored []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/filters":
			mu.Lock()
			items := []map[string]any{{"id": serverIDListed, "criteria": map[string]string{"from": "noreply@vendor.example"}}}
			for _, s := range stored {
				// The server echoes stored criteria back as the object's id,
				// the reflection a writable field can produce.
				items = append(items, map[string]any{"id": s})
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"filter": items,
				// An ID that appears only as an object key issues nothing.
				"index": map[string]string{serverIDKeyOnly: "x"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/filters":
			var in struct {
				Criteria struct{ Query string } `json:"criteria"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			mu.Lock()
			if in.Criteria.Query != "" {
				stored = append(stored, in.Criteria.Query)
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"id": serverIDCreated})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/filters/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/secret-id":
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "AK" + "IA" + "Q9W8E7R6T5Y4U3I2"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, func(key string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits[key]
	}
}

// TestInterceptServerIssuedIDs drives a mail-style API through a real
// TLS-intercepted CONNECT. Each blocked row is an allowed row with exactly one
// piece of evidence taken away.
func TestInterceptServerIssuedIDs(t *testing.T) {
	const agent = "mail-agent"

	t.Run("an id names nothing until the origin issues it", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, hits := newMailAPI(t)
		if got := h.send(api, http.MethodDelete, "/filters/"+serverIDListed, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("delete before listing = %d, want 403", got)
		}
		if hits("DELETE /filters/"+serverIDListed) != 0 {
			t.Fatal("an unissued id reached upstream")
		}
	})

	t.Run("a listed id may be named back to its origin", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, hits := newMailAPI(t)
		if got := h.send(api, http.MethodGet, "/filters", agent, "", ""); got != http.StatusOK {
			t.Fatalf("list = %d", got)
		}
		if got := h.send(api, http.MethodDelete, "/filters/"+serverIDListed, agent, "", ""); got != http.StatusNoContent {
			t.Fatalf("delete listed id = %d, want 204", got)
		}
		if hits("DELETE /filters/"+serverIDListed) != 1 {
			t.Fatal("the issued id did not reach upstream")
		}
	})

	t.Run("an id a create response returned may be named back", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		if got := h.send(api, http.MethodPost, "/filters", agent, "application/json", `{"criteria":{"from":"a@vendor.example"}}`); got != http.StatusOK {
			t.Fatalf("create = %d", got)
		}
		if got := h.send(api, http.MethodDelete, "/filters/"+url.PathEscape(serverIDCreated), agent, "", ""); got != http.StatusNoContent {
			t.Fatalf("delete created id = %d, want 204", got)
		}
	})

	t.Run("a value the agent sent and the origin echoed is not issued", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, hits := newMailAPI(t)
		if got := h.send(api, http.MethodPost, "/filters", agent, "application/json", `{"criteria":{"query":"`+agentBlob+`"}}`); got != http.StatusOK {
			t.Fatalf("create with blob = %d", got)
		}
		if got := h.send(api, http.MethodGet, "/filters", agent, "", ""); got != http.StatusOK {
			t.Fatalf("list = %d", got)
		}
		if got := h.send(api, http.MethodDelete, "/filters/"+agentBlob, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("reflected blob as id = %d, want 403", got)
		}
		if hits("DELETE /filters/"+agentBlob) != 0 {
			t.Fatal("a reflected value reached upstream as an id")
		}
	})

	t.Run("a value escaped in the request body is still recorded as sent", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, hits := newMailAPI(t)
		escaped := string([]byte{0x5c}) + "u004b" + agentBlob[1:] // "K" written as a JSON escape
		if got := h.send(api, http.MethodPost, "/filters", agent, "application/json", `{"criteria":{"query":"`+escaped+`"}}`); got != http.StatusOK {
			t.Fatalf("create = %d", got)
		}
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		if got := h.send(api, http.MethodDelete, "/filters/"+agentBlob, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("escaped reflection as id = %d, want 403", got)
		}
		if hits("DELETE /filters/"+agentBlob) != 0 {
			t.Fatal("an escaped reflection reached upstream as an id")
		}
	})

	t.Run("a value the agent sent in a header and the origin echoed is not issued", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		if got := h.sendHeader(api, http.MethodPost, "/filters", agent, "X-Note", agentBlob, `{"criteria":{"from":"a@vendor.example"}}`); got != http.StatusOK {
			t.Fatalf("create = %d", got)
		}
		api2Store(t, h, agent, api, agentBlob)
		if got := h.send(api, http.MethodDelete, "/filters/"+agentBlob, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("header reflection as id = %d, want 403", got)
		}
	})

	t.Run("a value the agent sent as a form field and the origin echoed is not issued", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		if got := h.send(api, http.MethodPost, "/filters", agent, "application/x-www-form-urlencoded", "payload="+agentBlob); got != http.StatusOK {
			t.Fatalf("form post = %d", got)
		}
		api2Store(t, h, agent, api, agentBlob)
		if got := h.send(api, http.MethodDelete, "/filters/"+agentBlob, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("form reflection as id = %d, want 403", got)
		}
	})

	t.Run("an issued id does not cross to another origin", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		other, otherHits := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		if got := h.send(other, http.MethodDelete, "/filters/"+serverIDListed, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("id on another origin = %d, want 403", got)
		}
		if otherHits("DELETE /filters/"+serverIDListed) != 0 {
			t.Fatal("an id issued by one origin reached another")
		}
	})

	t.Run("an issued id does not cross to another agent", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		if got := h.send(api, http.MethodDelete, "/filters/"+serverIDListed, "other-agent", "", ""); got != http.StatusForbidden {
			t.Fatalf("id for another agent = %d, want 403", got)
		}
	})

	t.Run("one changed character is a different value", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		mutated := serverIDListed[:len(serverIDListed)-1] + "X"
		if got := h.send(api, http.MethodDelete, "/filters/"+mutated, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("mutated id = %d, want 403", got)
		}
	})

	t.Run("another high-entropy segment beside an issued id still blocks", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		if got := h.send(api, http.MethodDelete, "/filters/"+serverIDListed+"/"+serverIDOther, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("issued id plus unissued segment = %d, want 403", got)
		}
	})

	t.Run("an object key issues nothing", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, _ := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/filters", agent, "", "")
		if got := h.send(api, http.MethodDelete, "/filters/"+serverIDKeyOnly, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("key-only id = %d, want 403", got)
		}
	})

	t.Run("an issued id that is a credential is still DLP-blocked", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		api, hits := newMailAPI(t)
		_ = h.send(api, http.MethodGet, "/secret-id", agent, "", "")
		secret := "AK" + "IA" + "Q9W8E7R6T5Y4U3I2"
		if got := h.send(api, http.MethodDelete, "/filters/"+secret, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("credential-shaped issued id = %d, want 403", got)
		}
		if hits("DELETE /filters/"+secret) != 0 {
			t.Fatal("a credential reached upstream")
		}
	})
}

func newTestServerIDStore(t *testing.T) *issuerQueryStore {
	t.Helper()
	s := newIssuerQueryStore()
	if s.disabled {
		t.Fatal("store disabled")
	}
	return s
}

func TestIssuerServerIDAddressing(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	now := time.Now()
	s := newTestServerIDStore(t)
	s.recordSent("owner", origin, nil, nil, true, now)
	s.mintServerID("owner", origin, serverIDListed, now)
	for _, tc := range []struct {
		name, segment string
		want          bool
	}{
		{"bare", serverIDListed, true},
		{"delimiter", serverIDListed + ":", true},
		{"two delimiters", serverIDListed + "::", false},
		{"prefix", ":" + serverIDListed, false},
		{"suffix payload", serverIDListed + ":" + agentBlob, false},
		{"other punctuation", serverIDListed + ";", false},
		{"empty ID", ":", false},
		{"unissued", serverIDOther + ":", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.serverIDIssued("owner", origin, tc.segment); got != tc.want {
				t.Fatalf("issued = %v, want %v", got, tc.want)
			}
		})
	}
	// A literal colon is a pchar too. Returning a colon-bearing ID issues that
	// exact value, never the different value with its final colon removed.
	s.mintServerID("owner", origin, serverIDOther+":", now)
	if !s.serverIDIssued("owner", origin, serverIDOther+":") || s.serverIDIssued("owner", origin, serverIDOther) {
		t.Fatal("literal colon ID changed identity")
	}
	for i := range issuerCookieMaxEntries {
		s.mintServerID("owner", origin, fmt.Sprintf("object-identifier-%016d", i), now)
	}
	if s.serverIDIssued("owner", origin, serverIDListed+":") {
		t.Fatal("evicted ID retained addressing allowance")
	}
	if newTestServerIDStore(t).serverIDIssued("owner", origin, serverIDListed+":") {
		t.Fatal("fresh store retained addressing allowance")
	}
}

func TestIssuerServerIDHistoryRequired(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	now := time.Now()
	t.Run("mint requires recorded send", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.mintServerID("owner", origin, serverIDListed, now)
		if len(s.ids) != 0 || len(s.history) != 0 {
			t.Fatal("missing send history created ID authority or a history bucket")
		}
		s.recordSent("owner", origin, nil, nil, true, now)
		s.mintServerID("owner", origin, serverIDListed, now)
		if !s.serverIDIssued("owner", origin, serverIDListed) {
			t.Fatal("recorded complete request did not permit response ID")
		}
	})
	t.Run("lookup cannot consume history capacity", func(t *testing.T) {
		s := newTestServerIDStore(t)
		observations := 0
		s.observeIDBlock = func(string, bool) { observations++ }
		for i := 0; i <= issuerUnreadableMaxSessions; i++ {
			if s.serverIDIssued(fmt.Sprintf("lookup-%d", i), origin, serverIDListed) {
				t.Fatal("lookup admitted an unissued ID")
			}
		}
		if len(s.history) != 0 || s.idCapacityReported || observations != 0 {
			t.Fatal("read-only lookups changed history or capacity observations")
		}
		s.recordSent("peer", origin, nil, nil, true, now)
		s.mintServerID("peer", origin, serverIDListed, now)
		if !s.serverIDIssued("peer", origin, serverIDListed) {
			t.Fatal("lookups prevented a later real caller from learning an ID")
		}
	})
	t.Run("exact proofs cannot restore learning history", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.recordSent("owner", origin, nil, nil, true, now)
		s.mintServerID("owner", origin, serverIDListed, now)
		if !s.serverIDIssued("owner", origin, serverIDListed) {
			t.Fatal("positive control: recorded response ID unavailable")
		}
		delete(s.history, "owner")
		s.mintServerID("owner", origin, serverIDOther, now)
		if !s.serverIDIssued("owner", origin, serverIDListed) || s.serverIDIssued("owner", origin, serverIDOther) || len(s.history) != 0 {
			t.Fatal("orphaned ID restored missing history")
		}
	})
}

func TestIssuerServerIDStore(t *testing.T) {
	origin, _ := url.Parse("https://api.vendor.example/v1/filters")
	now := time.Now()

	t.Run("an unread request body stops minting", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.recordSent("a", origin, nil, nil, false, now)
		s.mintServerID("a", origin, serverIDListed, now)
		if s.serverIDIssued("a", origin, serverIDListed) {
			t.Fatal("minted after an unread body")
		}
	})

	t.Run("an unread body preserves ids minted before it", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.recordSent("a", origin, nil, nil, true, now)
		s.mintServerID("a", origin, serverIDListed, now)
		if !s.serverIDIssued("a", origin, serverIDListed) {
			t.Fatal("positive control: id not minted")
		}
		s.recordSent("a", origin, nil, nil, false, now)
		if !s.serverIDIssued("a", origin, serverIDListed) {
			t.Fatal("known id lost after unread body")
		}
	})

	t.Run("a request over the token bound stops minting", func(t *testing.T) {
		s := newTestServerIDStore(t)
		var b strings.Builder
		for i := 0; i <= issuerSentMaxTokensPerRequest; i++ {
			b.WriteString(serverIDOther)
			b.WriteByte(' ')
			b.WriteString(strings.Repeat("Q", 16+i%7))
			b.WriteByte(' ')
		}
		s.recordSent("a", origin, nil, []byte(b.String()), true, now)
		s.mintServerID("a", origin, serverIDListed, now)
		if s.serverIDIssued("a", origin, serverIDListed) {
			t.Fatal("minted after an over-bound request")
		}
	})

	t.Run("a value sent in a query is never minted", func(t *testing.T) {
		s := newTestServerIDStore(t)
		withQuery, _ := url.Parse("https://api.vendor.example/search?q=" + agentBlob)
		s.recordSent("a", withQuery, nil, nil, true, now)
		s.mintServerID("a", origin, agentBlob, now)
		if s.serverIDIssued("a", origin, agentBlob) {
			t.Fatal("a query value was minted")
		}
	})

	t.Run("sent evidence is per origin", func(t *testing.T) {
		s := newTestServerIDStore(t)
		other, _ := url.Parse("https://other.vendor.example/upload")
		s.recordSent("a", other, nil, []byte(agentBlob), true, now)
		s.recordSent("a", origin, nil, nil, true, now)
		s.mintServerID("a", origin, agentBlob, now)
		if !s.serverIDIssued("a", origin, agentBlob) {
			t.Fatal("a value sent to a different origin blocked minting on this one")
		}
	})

	t.Run("one malformed escape does not hide the rest of a form body", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.recordSent("a", origin, nil, []byte("bad=%ZZ&payload="+agentBlob[:10]+"%2B"+agentBlob[10:]), true, now)
		withPlus := agentBlob[:10] + "+" + agentBlob[10:]
		s.mintServerID("a", origin, withPlus, now)
		if s.serverIDIssued("a", origin, withPlus) {
			t.Fatal("a percent-decoded form value was minted")
		}
	})

	t.Run("a header value is recorded as sent", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.recordSent("a", origin, http.Header{"Cookie": {"sid=" + agentBlob}}, nil, true, now)
		s.mintServerID("a", origin, agentBlob, now)
		if s.serverIDIssued("a", origin, agentBlob) {
			t.Fatal("a cookie value was minted")
		}
	})

	t.Run("bucket capacity refuses newcomers without revoking peers", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.recordSent("existing", origin, nil, nil, true, now)
		s.mintServerID("existing", origin, serverIDListed, now)
		for i := 1; i < issuerUnreadableMaxSessions; i++ {
			s.freezeIDCallerLocked(fmt.Sprintf("tainted-%d", i))
		}
		var events []string
		s.observeIDBlock = func(scope string, log bool) { events = append(events, fmt.Sprintf("%s:%t", scope, log)) }
		s.freezeIDCallerLocked("one-more")
		s.mintServerID("newcomer", origin, serverIDOther, now)
		if s.serverIDIssued("newcomer", origin, serverIDOther) || len(s.history) != issuerUnreadableMaxSessions {
			t.Fatal("new bucket admitted past capacity")
		}
		if !s.serverIDIssued("existing", origin, serverIDListed) {
			t.Fatal("capacity revoked existing peer")
		}
		if len(events) != 1 || events[0] != "capacity:true" {
			t.Fatalf("capacity events = %v", events)
		}
	})

	t.Run("send history is isolated across trusted sessions", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.recordSent("a", origin, nil, []byte(agentBlob), true, now)
		s.mintServerID("a", origin, agentBlob, now)
		if s.serverIDIssued("a", origin, agentBlob) {
			t.Fatal("own reflection minted")
		}
		s.recordSent("b", origin, nil, nil, true, now)
		s.mintServerID("b", origin, agentBlob, now)
		if !s.serverIDIssued("b", origin, agentBlob) {
			t.Fatal("another caller's sends poisoned recipient")
		}
	})

	t.Run("a value sent to the host over plain http or another port is not minted", func(t *testing.T) {
		for _, raw := range []string{"http://api.vendor.example/notes?x=" + agentBlob, "https://api.vendor.example:8443/notes?x=" + agentBlob} {
			s := newTestServerIDStore(t)
			sentTo, _ := url.Parse(raw)
			s.recordSent("a", sentTo, nil, nil, true, now)
			s.mintServerID("a", origin, agentBlob, now)
			if s.serverIDIssued("a", origin, agentBlob) {
				t.Fatalf("value sent via %s was minted", raw)
			}
		}
	})

	t.Run("total history capacity taints only the adding caller", func(t *testing.T) {
		s := newTestServerIDStore(t)
		s.recordSent("peer", origin, nil, nil, true, now)
		s.mintServerID("peer", origin, serverIDListed, now)
		s.sentEntries = issuerSentAllMaxEntries
		s.recordSent("a", origin, nil, []byte(serverIDOther), true, now)
		s.mintServerID("a", origin, serverIDListed, now)
		if s.serverIDIssued("a", origin, serverIDListed) {
			t.Fatal("adding caller did not fail closed")
		}
		if !s.serverIDIssued("peer", origin, serverIDListed) {
			t.Fatal("capacity revoked peer")
		}
	})

	t.Run("shape bounds", func(t *testing.T) {
		for _, v := range []string{"short", strings.Repeat("a", issuerServerIDMaxLen+1), "has/slash" + serverIDListed, "has space" + serverIDListed, "pct%41" + serverIDListed} {
			if issuerServerIDShaped(v) {
				t.Fatalf("%q accepted as an id", v)
			}
		}
		if !issuerServerIDShaped(serverIDCreated) {
			t.Fatal("padded base64url id rejected")
		}
	})

	t.Run("plain http origin is ignored", func(t *testing.T) {
		s := newTestServerIDStore(t)
		plain, _ := url.Parse("http://api.vendor.example/v1/filters")
		s.recordSent("a", origin, nil, nil, true, now)
		s.mintServerID("a", origin, serverIDListed, now)
		if !s.serverIDIssued("a", origin, serverIDListed) {
			t.Fatal("positive control: HTTPS origin did not mint an ID")
		}
		issued := s.idCount("a")
		s.mintServerID("a", plain, serverIDOther, now)
		if s.idCount("a") != issued {
			t.Fatal("plain http changed issued ID evidence")
		}
		if s.serverIDIssued("a", plain, serverIDListed) {
			t.Fatal("plain http minted an id")
		}
		if !s.serverIDIssued("a", origin, serverIDListed) {
			t.Fatal("plain http revoked HTTPS evidence")
		}
	})
}

// Sends outside TLS interception still reach origins the store holds IDs for:
// a /fetch URL is recorded as sent, and a WebSocket handshake stops minting
// for the session, because its frames are not recorded token by token.
func TestIssuerServerIDUnmediatedSends(t *testing.T) {
	origin, _ := url.Parse("https://api.vendor.example/v1/filters")
	now := time.Now()
	const agent = "mail-agent"

	t.Run("a fetch URL is recorded as sent", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		store := h.p.issuerStoreForUnmediatedSend()
		if store == nil {
			t.Fatal("positive control: issuer store not running")
		}
		withBlob, _ := url.Parse("https://api.vendor.example/notes/" + agentBlob)
		h.p.recordIssuerFetchSent(h.cfg, agent, "127.0.0.1", envelope.ActorAuthBound, withBlob)
		session := sessionKeyFor(h.cfg, agent, "127.0.0.1", envelope.ActorAuthBound)
		store.mintServerID(session, origin, agentBlob, now)
		if store.serverIDIssued(session, origin, agentBlob) {
			t.Fatal("a value sent through /fetch was minted")
		}
	})

	t.Run("a plain-http forward request is recorded as sent", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		store := h.p.issuerStoreForUnmediatedSend()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://api.vendor.example/notes/"+agentBlob, nil)
		h.p.recordIssuerForwardSent(h.cfg, agent, "127.0.0.1", envelope.ActorAuthBound, req, nil)
		session := sessionKeyFor(h.cfg, agent, "127.0.0.1", envelope.ActorAuthBound)
		store.mintServerID(session, origin, agentBlob, now)
		if store.serverIDIssued(session, origin, agentBlob) {
			t.Fatal("a value sent through the plain-http forward proxy was minted")
		}
	})

	t.Run("an unread plain-http forward body stops minting", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		store := h.p.issuerStoreForUnmediatedSend()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://api.vendor.example/notes", strings.NewReader(agentBlob))
		h.p.recordIssuerForwardSent(h.cfg, agent, "127.0.0.1", envelope.ActorAuthBound, req, nil)
		session := sessionKeyFor(h.cfg, agent, "127.0.0.1", envelope.ActorAuthBound)
		store.mintServerID(session, origin, serverIDListed, now)
		if store.serverIDIssued(session, origin, serverIDListed) {
			t.Fatal("minted after an unread forward body")
		}
	})

	t.Run("a websocket handshake stops minting for the session", func(t *testing.T) {
		h := newWebPlatformHarness(t)
		store := h.p.issuerStoreForUnmediatedSend()
		session := sessionKeyFor(h.cfg, agent, "127.0.0.1", envelope.ActorAuthBound)
		store.recordSent(session, origin, nil, nil, true, now)
		store.mintServerID(session, origin, serverIDListed, now)
		if !store.serverIDIssued(session, origin, serverIDListed) {
			t.Fatal("positive control: id not minted")
		}
		h.p.taintIssuerSessionForStream(h.cfg, agent, "127.0.0.1", envelope.ActorAuthBound, origin)
		if !store.serverIDIssued(session, origin, serverIDListed) {
			t.Fatal("known id lost after websocket handshake")
		}
	})
}

// A gzip or deflate body is what the origin application reads. History has to
// record that plaintext. Recording only the compressed bytes lets the origin
// echo an identifier the session already sent, and path entropy then treats
// the echo as server-issued.
func TestIssuerHistorySeesPlaintextInsideCompressedRequest(t *testing.T) {
	origin, err := url.Parse("https://api.vendor.example/v1/filters")
	if err != nil {
		t.Fatal(err)
	}
	const agent = "mail-agent"
	now := time.Now()
	// Default compression of a short literal stores it unchanged. A repeated
	// prefix is long enough that the default compressor stops storing the
	// identifier as a contiguous byte string, which is what ordinary clients
	// send.
	plain := append(bytes.Repeat([]byte("note "), 40), []byte(agentBlob)...)
	gzipBody := gzipIssuerBody(t, plain)
	deflateBody := zlibIssuerBody(t, plain)
	if bytes.Contains(gzipBody, []byte(agentBlob)) || bytes.Contains(deflateBody, []byte(agentBlob)) {
		t.Fatal("fixture left the identifier visible in the compressed bytes")
	}

	type call struct {
		name      string
		encoding  string
		body      []byte
		intercept bool
		// otherIDMinted is false when the coding cannot be decoded: learning
		// stops, so an identifier that was not in the body cannot mint either.
		otherIDMinted bool
		// decodeLimit overrides the store's decoded-size limit when set.
		decodeLimit int
	}
	corrupt := append([]byte(nil), gzipBody...)
	corrupt[len(corrupt)-1] ^= 0xff
	cases := []call{
		{name: "identity", body: []byte(agentBlob), otherIDMinted: true},
		{name: "gzip forward", encoding: "gzip", body: gzipBody, otherIDMinted: true},
		{name: "x-gzip forward", encoding: "x-gzip", body: gzipBody, otherIDMinted: true},
		{name: "deflate forward", encoding: "deflate", body: deflateBody, otherIDMinted: true},
		{name: "gzip intercept", encoding: "gzip", body: gzipBody, intercept: true, otherIDMinted: true},
		{name: "unsupported coding", encoding: "br", body: []byte("notes"), otherIDMinted: false},
		{name: "truncated gzip", encoding: "gzip", body: gzipBody[:len(gzipBody)-6], otherIDMinted: false},
		{name: "corrupt gzip checksum", encoding: "gzip", body: corrupt, otherIDMinted: false},
		{name: "bytes after gzip", encoding: "gzip", body: append(append([]byte(nil), gzipBody...), "tail"...), otherIDMinted: false},
		{name: "second gzip member", encoding: "gzip", body: append(append([]byte(nil), gzipBody...), gzipIssuerBody(t, []byte("more"))...), otherIDMinted: false},
		{name: "bytes after deflate", encoding: "deflate", body: append(append([]byte(nil), deflateBody...), "tail"...), otherIDMinted: false},
		{name: "decoded size over the limit", encoding: "gzip", body: gzipBody, decodeLimit: 16, otherIDMinted: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newWebPlatformHarness(t)
			store := h.p.issuerStoreForUnmediatedSend()
			if store == nil {
				t.Fatal("issuer store not running")
			}
			if tc.decodeLimit > 0 {
				store.bodyDecodeLimit = func() int { return tc.decodeLimit }
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.vendor.example/notes", bytes.NewReader(tc.body))
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}
			if tc.intercept {
				recordIssuerRequestSent(&InterceptContext{
					Proxy: h.p, Config: h.cfg, Agent: agent, ClientIP: "127.0.0.1", ActorAuth: envelope.ActorAuthBound,
				}, req, tc.body)
			} else {
				h.p.recordIssuerForwardSent(h.cfg, agent, "127.0.0.1", envelope.ActorAuthBound, req, append([]byte(nil), tc.body...))
			}
			session := sessionKeyFor(h.cfg, agent, "127.0.0.1", envelope.ActorAuthBound)
			store.mintServerID(session, origin, agentBlob, now)
			if store.serverIDIssued(session, origin, agentBlob) {
				t.Fatal("identifier carried to the origin was minted")
			}
			store.mintServerID(session, origin, serverIDListed, now)
			if got := store.serverIDIssued(session, origin, serverIDListed); got != tc.otherIDMinted {
				t.Fatalf("unrelated id minted=%v, want %v", got, tc.otherIDMinted)
			}
		})
	}
}

func gzipIssuerBody(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zlibIssuerBody(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
