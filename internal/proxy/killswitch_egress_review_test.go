// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0
package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestKillSwitchEgressRedirectEvidence(t *testing.T) {
	for _, mode := range []string{"fetch", "forward"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.APIAllowlist = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
			cfg.ForwardProxy.Enabled = true
			ks := killswitch.New(cfg)
			var originURL string
			origin := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					ks.SetAPI(true)
					http.Redirect(w, r, strings.Replace(originURL, "127.0.0.1", "localhost", 1)+"/end", http.StatusFound)
					return
				}
				t.Error("redirect target reached")
				_, _ = io.WriteString(w, "bad")
			}))
			defer origin.Close()
			originURL = origin.URL
			rph := newReceiptProxyHelper(t)
			p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New(), WithKillSwitch(ks), WithRecorder(rph.rec), WithReceiptEmitter(rph.emitter))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			// Forward never follows redirects (they return to the client), so the
			// forward case checks the first-hop denial and its receipt target; the
			// fetch case is the one that exercises a refused redirect hop.
			if mode == "forward" {
				inner := p.client.Transport
				p.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) { ks.SetAPI(true); return inner.RoundTrip(req) })
			}
			target := origin.URL + "/start"
			if mode == "fetch" {
				target = "/fetch?url=" + target
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			w := httptest.NewRecorder()
			p.buildHandler(p.buildMux()).ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("status %d", w.Code)
			}
			if got := w.Header().Get(blockreason.HeaderReason); got != string(blockreason.KillSwitchActive) {
				t.Errorf("reason = %q want %q", got, blockreason.KillSwitchActive)
			}
			rec := rph.requireReceipt(t, "kill_switch")
			if got := w.Header().Get(blockreason.HeaderRecordedReceipt); got != rec.ActionRecord.ActionID {
				t.Errorf("recorded receipt header = %q, want %q", got, rec.ActionRecord.ActionID)
			}
			wantTarget := origin.URL
			if mode == "fetch" {
				wantTarget = strings.Replace(origin.URL, "127.0.0.1", "localhost", 1)
			}
			if got := rec.ActionRecord.Target; got != wantTarget {
				t.Errorf("receipt target = %q want %q", got, wantTarget)
			}
		})
	}
}

func TestKillSwitchEgressArtifactEvidence(t *testing.T) {
	cfg := artifactConfig()
	cfg.ForwardProxy.Enabled = true
	ks := killswitch.New(cfg)
	rph := newReceiptProxyHelper(t)
	p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New(), WithKillSwitch(ks), WithRecorder(rph.rec), WithReceiptEmitter(rph.emitter))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var calls int
	egress := p.client.Transport.(killSwitchEgressTransport)
	egress.next = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		ks.SetAPI(true)
		return artifactResponse(req, http.StatusOK, artifactBundle("safe")), nil
	})
	p.client.Transport = egress
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://rules.example"+artifactIntegrationPath, nil)
	w := httptest.NewRecorder()
	p.buildHandler(p.buildMux()).ServeHTTP(w, req)
	if calls != 1 {
		t.Errorf("upstream calls = %d, want 1", calls)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d", w.Code)
	}
	if got := w.Header().Get(blockreason.HeaderReason); got != string(blockreason.KillSwitchActive) {
		t.Errorf("reason = %q, want %q", got, blockreason.KillSwitchActive)
	}
	rec := rph.requireReceipt(t, "kill_switch")
	if got := w.Header().Get(blockreason.HeaderRecordedReceipt); got != rec.ActionRecord.ActionID {
		t.Errorf("recorded receipt header = %q, want %q", got, rec.ActionRecord.ActionID)
	}
	if rec.ActionRecord.Verdict != config.ActionBlock {
		t.Errorf("verdict = %q", rec.ActionRecord.Verdict)
	}
}
