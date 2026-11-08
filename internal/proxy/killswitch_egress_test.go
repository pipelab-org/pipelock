// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A kill switch thrown after a fetch is admitted must stop its next egress.
// The origin throws the switch and answers with a redirect to itself; the
// redirect hop reuses the kept-alive connection, so only a per-request check
// can see it.
func TestFetchKillSwitchStopsRedirectHop(t *testing.T) {
	for _, tc := range []struct {
		name      string
		activate  bool
		allowlist []string
		wantFinal bool
	}{
		{name: "switch_thrown_mid_fetch", activate: true, wantFinal: false},
		{name: "no_switch", activate: false, wantFinal: true},
		{name: "allowlisted_client_ip_exempt", activate: true, allowlist: []string{"192.0.2.0/24"}, wantFinal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.FetchProxy.TimeoutSeconds = 5
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
			cfg.APIAllowlist = nil
			cfg.KillSwitch.AllowlistIPs = tc.allowlist
			ks := killswitch.New(cfg)
			var finalHits atomic.Int32
			origin := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == testFinalPath {
					finalHits.Add(1)
					_, _ = io.WriteString(w, "reached")
					return
				}
				if tc.activate {
					ks.SetAPI(true)
				}
				http.Redirect(w, r, testFinalPath, http.StatusFound)
			}))
			defer origin.Close()

			p, err := New(cfg, audit.NewNop(), scanner.MustNew(cfg), metrics.New(), WithKillSwitch(ks))
			if err != nil {
				t.Fatalf("proxy.New: %v", err)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+origin.URL+"/start", nil)
			// httptest requests come from 192.0.2.1 (TEST-NET-1).
			w := httptest.NewRecorder()
			mux := http.NewServeMux()
			mux.HandleFunc("/fetch", p.handleFetch)
			mux.ServeHTTP(w, req)

			reached := finalHits.Load() > 0
			if reached != tc.wantFinal {
				t.Fatalf("redirect target reached = %v, want %v (status %d, body %.200s)", reached, tc.wantFinal, w.Code, w.Body.String())
			}
			if !tc.wantFinal {
				if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), killSwitchActiveReason) {
					t.Fatalf("want 403 naming the kill switch, got %d %.200s", w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestKillSwitchEgressTransport(t *testing.T) {
	cfg := config.Defaults()
	cfg.KillSwitch.AllowlistIPs = []string{"198.51.100.0/24"}
	ks := killswitch.New(cfg)
	var nextCalls atomic.Int32
	rt := killSwitchEgressTransport{
		next: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			nextCalls.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
		ks: ks,
	}
	newReq := func(clientIP string) (*http.Request, *closeTrackingBody) {
		body := &closeTrackingBody{Reader: strings.NewReader("payload")}
		ctx := t.Context()
		if clientIP != "" {
			ctx = context.WithValue(ctx, ctxKeyClientIP, clientIP)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.vendor.example/upload", body)
		if err != nil {
			t.Fatal(err)
		}
		return req, body
	}

	req, _ := newReq("203.0.113.7")
	resp, err := rt.RoundTrip(req)
	if err != nil || nextCalls.Load() != 1 {
		t.Fatalf("inactive switch must pass through: err=%v calls=%d", err, nextCalls.Load())
	}
	_ = resp.Body.Close()

	ks.SetAPI(true)
	for _, ip := range []string{"203.0.113.7", ""} {
		req, body := newReq(ip)
		resp, err := rt.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		var blocked *blockedRequestError
		if !errors.As(err, &blocked) || blocked.layer != "kill_switch" {
			t.Fatalf("client %q: want kill_switch block, got %v", ip, err)
		}
		if !body.closed {
			t.Fatalf("client %q: refused request body was not closed", ip)
		}
	}
	if nextCalls.Load() != 1 {
		t.Fatalf("blocked requests reached the next transport: calls=%d", nextCalls.Load())
	}

	req, _ = newReq("198.51.100.9")
	if resp, err = rt.RoundTrip(req); err != nil {
		t.Fatalf("allowlisted client must stay exempt at egress: %v", err)
	}
	_ = resp.Body.Close()

	nilKS := killSwitchEgressTransport{next: rt.next}
	req, _ = newReq("203.0.113.7")
	if resp, err = nilKS.RoundTrip(req); err != nil {
		t.Fatalf("no controller configured must pass through: %v", err)
	}
	_ = resp.Body.Close()
}
