// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestWatchOnlyInterceptRefusesUninspectedUpgrade(t *testing.T) {
	upstreamHost := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHost <- r.Host
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			t.Errorf("upstream Upgrade: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Errorf("upstream deadline: %v", err)
			return
		}
		for {
			payload, opcode, err := wsutil.ReadClientData(conn)
			if err != nil {
				return
			}
			if err := wsutil.WriteServerMessage(conn, opcode, payload); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(target.Host)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal, cfg.WatchOnly = nil, true
	sc := scanner.MustNew(cfg)
	m := metrics.New()
	p, err := New(cfg, audit.NewNop(), sc, m)
	if err != nil {
		sc.Close()
		t.Fatal(err)
	}
	defer p.Close()
	// Exercise the handler used after CONNECT TLS termination, with a real
	// TLS upstream whose certificate is trusted by the test transport.
	handler := newInterceptHandler(&InterceptContext{
		TargetHost: host, TargetPort: port, Config: cfg, Scanner: sc,
		Logger: audit.NewNop(), Metrics: m, Proxy: p,
	}, upstream.Client().Transport)
	intercept := httptest.NewServer(handler)
	defer intercept.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := wsTestDial(ctx, ws.Dialer{Host: target.Host}, "ws"+strings.TrimPrefix(intercept.URL, "http")+"/socket")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("uninspected intercepted WebSocket was upgraded")
	}
}
