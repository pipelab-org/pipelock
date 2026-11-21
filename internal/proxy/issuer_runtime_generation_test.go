// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// openTunnel starts one long-lived intercepted tunnel to host:443 the way the
// forward proxy does: the issuer runtime is snapshotted when the tunnel opens
// and the tunnel keeps its configuration and scanner for its whole life.
// The returned function sends one keep-alive request on that same tunnel.
func (e *delegationEnv) openTunnel(agent, host string) func(rawURL string) int {
	e.t.Helper()
	clientConn, proxyConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	e.t.Cleanup(func() { cancel(); _ = clientConn.Close() })
	cfg, sc := e.cfg, e.sc
	go func() {
		_ = interceptTunnel(ctx, proxyConn, &InterceptContext{
			TargetHost: host, TargetPort: "443", Config: cfg, Scanner: sc, CertCache: e.cache,
			Logger: e.logger, Metrics: e.m, ClientIP: "10.0.0.1", RequestID: "long-lived-tunnel",
			UpstreamRT: e.rt, Proxy: e.p, Agent: agent, ActorAuth: envelope.ActorAuthBound,
			IssuerRuntime: e.p.issuerCookieRuntime.Load(),
		})
	}()
	tlsConn := tls.Client(clientConn, &tls.Config{RootCAs: e.pool, ServerName: host})
	e.t.Cleanup(func() { _ = tlsConn.Close() })
	reader := bufio.NewReader(tlsConn)
	return func(rawURL string) int {
		e.t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
		if err != nil {
			e.t.Fatal(err)
		}
		if err := req.Write(tlsConn); err != nil {
			e.t.Fatalf("write request: %v", err)
		}
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			e.t.Fatalf("read response: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
}

// TestIssuerEvidenceSurvivesUnrelatedReloadOnOpenTunnel reproduces a browser
// that keeps one tunnel open across a nightly reload. Evidence it gathered
// must keep working while the evidence window is carried forward, and must
// stop when a reload closes that window.
func TestIssuerEvidenceSurvivesUnrelatedReloadOnOpenTunnel(t *testing.T) {
	first, second := joinedCardHalves()
	query := "wo=" + first + "&site=" + second
	issued := joinedDetailURL(delegationSourceHost, query)
	page := "https://" + delegationSourceHost + "/records/list"
	target, _ := url.Parse(issued)

	e := newSameOriginEnv(t, nil)
	e.servePage(joinedDetailPath + "?" + query)
	send := e.openTunnel("agent-one", delegationSourceHost)
	if got := send(page); got != http.StatusOK {
		t.Fatalf("page status = %d, want 200", got)
	}
	if got := send(issued); got != http.StatusOK {
		t.Fatalf("before reload status = %d, want 200", got)
	}
	pinned := e.p.issuerCookieRuntime.Load()
	diag := &InterceptContext{Proxy: e.p, Config: e.cfg, Agent: "agent-one", ClientIP: "10.0.0.1", ActorAuth: envelope.ActorAuthBound, IssuerRuntime: pinned}

	unrelated := e.cfg.Clone()
	unrelated.FetchProxy.Monitoring.MaxReqPerMinute++
	e.reload(unrelated)
	if e.p.issuerCookieRuntime.Load() == pinned {
		t.Fatal("premise: an enabled reload publishes a new runtime pointer")
	}
	if got := send(issued); got != http.StatusOK {
		t.Fatalf("after unrelated reload status = %d on the open tunnel, want 200", got)
	}
	if reason := diag.issuerIDBlockReason(target); reason == "stale_runtime" {
		t.Fatal("diagnostics report stale_runtime for a carried-forward evidence window")
	}

	identity := e.cfg.Clone()
	identity.DefaultAgentIdentity = "default-owner"
	e.reload(identity)
	if got := send(issued); got != http.StatusForbidden {
		t.Fatalf("after identity reload status = %d on the open tunnel, want 403", got)
	}
	restoredIdentity := e.cfg.Clone()
	restoredIdentity.DefaultAgentIdentity = unrelated.DefaultAgentIdentity
	e.reload(restoredIdentity)

	off := e.cfg.Clone()
	off.RequestBodyScanning.IssuerBoundSessionCookies = false
	e.reload(off)
	if got := send(issued); got != http.StatusForbidden {
		t.Fatalf("after disabling reload status = %d on the open tunnel, want 403", got)
	}
	if reason := diag.issuerIDBlockReason(target); reason != "stale_runtime" {
		t.Fatalf("diagnostics after disabling reload = %q, want stale_runtime", reason)
	}

	on := e.cfg.Clone()
	on.RequestBodyScanning.IssuerBoundSessionCookies = true
	e.reload(on)
	if got := send(issued); got != http.StatusForbidden {
		t.Fatalf("after re-enable status = %d on the old tunnel, want 403: old evidence must not return", got)
	}
	fresh := e.openTunnel("agent-one", delegationSourceHost)
	if got := fresh(issued); got != http.StatusForbidden {
		t.Fatalf("re-enabled fresh tunnel status = %d, want 403 before the page is seen again", got)
	}
	if got := fresh(page); got != http.StatusOK {
		t.Fatalf("page status = %d, want 200", got)
	}
	if got := fresh(issued); got != http.StatusOK {
		t.Fatalf("re-enabled fresh tunnel after the page status = %d, want 200", got)
	}
}
