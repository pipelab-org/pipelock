// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

func TestIssuerIDHistoryBlockReason(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	for _, tc := range []struct {
		name    string
		prepare func(*issuerQueryStore, string)
		want    string
	}{
		{"missing", func(*issuerQueryStore, string) {}, "history_missing"},
		{"complete", func(s *issuerQueryStore, key string) {
			s.recordSent(key, origin, nil, nil, true, time.Now())
		}, "no_allowance"},
		{"unread body", func(s *issuerQueryStore, key string) {
			s.recordSent(key, origin, nil, nil, false, time.Now())
		}, "history_unread_body"},
		{"request limit", func(s *issuerQueryStore, key string) {
			s.recordSent(key, origin, nil, []byte(strings.Repeat(serverIDOther+" ", issuerSentMaxTokensPerRequest+1)), true, time.Now())
		}, "history_request_limit"},
		{"total limit", func(s *issuerQueryStore, key string) {
			s.sentEntries = issuerSentAllMaxEntries
			s.recordSent(key, origin, nil, []byte(serverIDOther), true, time.Now())
		}, "history_total_limit"},
		{"session limit", func(s *issuerQueryStore, key string) {
			s.recordSent(key, origin, nil, nil, true, time.Now())
			for i := range issuerSentMaxEntries {
				var digest [32]byte
				digest[0], digest[1] = byte(i), byte(i>>8)
				s.sent[key][digest] = issuerSentAgentFirst
			}
			s.recordSent(key, origin, nil, []byte(serverIDOther), true, time.Now())
		}, "history_session_limit"},
		{"stream", func(s *issuerQueryStore, key string) {
			s.taintSentForReasonLocked(key, issuerHistoryStream)
		}, "history_stream"},
		{"unspecified", func(s *issuerQueryStore, key string) {
			s.taintSentForReasonLocked(key, issuerHistoryComplete)
		}, "history_incomplete"},
		{"first cause retained", func(s *issuerQueryStore, key string) {
			s.recordSent(key, origin, nil, nil, false, time.Now())
			s.taintSentForReasonLocked(key, issuerHistoryStream)
		}, "history_unread_body"},
		{"bucket capacity", func(s *issuerQueryStore, _ string) {
			for i := range issuerUnreadableMaxSessions {
				s.sent[fmt.Sprintf("session-%d", i)] = nil
			}
		}, "history_capacity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, cfg := newSentIssuerProxy(t)
			ic := &InterceptContext{Proxy: p, Config: cfg, Agent: "reader", ClientIP: "192.0.2.1", ActorAuth: envelope.ActorAuthBound}
			s := p.issuerCookieRuntime.Load().query
			key := sessionKeyFor(cfg, ic.Agent, ic.ClientIP, ic.ActorAuth)
			tc.prepare(s, key)
			before := len(s.sent)
			if got := ic.issuerIDBlockReason(); got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
			if len(s.sent) != before {
				t.Fatal("diagnosis created send history")
			}
			if tc.want != "no_allowance" && s.serverIDIssued(key, origin, serverIDListed) {
				t.Fatal("diagnosis granted ID authority")
			}
		})
	}
}

func TestInterceptIssuerIDAuditReason(t *testing.T) {
	h := newWebPlatformHarness(t)
	var logs bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	h.logger, h.p.logger = logger, logger
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/list" {
			_, _ = io.WriteString(w, `{"id":"`+serverIDListed+`"}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(upstream.Close)
	const agent = "reader"
	if h.send(upstream, http.MethodGet, "/list", agent, "", "") != http.StatusOK ||
		h.send(upstream, http.MethodGet, "/items/"+serverIDListed, agent, "", "") != http.StatusOK {
		t.Fatal("positive control: discovery and issued item must succeed")
	}
	store := h.p.issuerCookieRuntime.Load().query
	key := sessionKeyFor(h.cfg, agent, "10.0.0.1", envelope.ActorAuthBound)
	origin := mustIssuerQueryURL(t, upstream.URL)
	store.recordSent(key, origin, nil, nil, false, time.Now())
	if got := h.send(upstream, http.MethodGet, "/items/"+serverIDListed, agent, "", ""); got != http.StatusForbidden {
		t.Fatalf("incomplete history = %d, want 403", got)
	}
	var block map[string]any
	for _, line := range strings.Split(logs.String(), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil && event["event"] == "blocked" {
			block = event
		}
	}
	if block["issuer_id_evidence"] != "history_unread_body" {
		t.Fatalf("operator diagnostic = %v", block["issuer_id_evidence"])
	}
	blockedJSON, err := json.Marshal(block)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blockedJSON, []byte(serverIDListed)) {
		t.Fatal("operator diagnostic exposed the matched ID")
	}
}

func TestIssuerIDBlockPrerequisites(t *testing.T) {
	var absent *InterceptContext
	if got := absent.issuerIDBlockReason(); got != "store_unavailable" {
		t.Fatal(got)
	}
	p, cfg := newSentIssuerProxy(t)
	ic := &InterceptContext{Proxy: p, Config: cfg, Agent: "reader", ClientIP: "192.0.2.1", ActorAuth: envelope.ActorAuthSelfDeclared}
	if got := ic.issuerIDBlockReason(); got != "untrusted_actor" {
		t.Fatal(got)
	}
	ic.ActorAuth = envelope.ActorAuthBound
	off := cfg.Clone()
	off.RequestBodyScanning.ScanHeaders = false
	ic.Config = off
	if got := ic.issuerIDBlockReason(); got != "disabled" {
		t.Fatal(got)
	}
	ic.Config = cfg.Clone()
	if got := ic.issuerIDBlockReason(); got != "stale_runtime" {
		t.Fatal(got)
	}
	ic.Config = cfg
	p.issuerCookieRuntime.Load().query.disabled = true
	if got := ic.issuerIDBlockReason(); got != "store_unavailable" {
		t.Fatal(got)
	}
	p.issuerCookieRuntime.Store(nil)
	if got := ic.issuerIDBlockReason(); got != "store_unavailable" {
		t.Fatal(got)
	}
}
