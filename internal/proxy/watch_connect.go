// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func (p *Proxy) handleWatchConnect(w http.ResponseWriter, r *http.Request, o watchHTTPOptions) {
	cfg, sc, agent := o.Config, o.Scanner, o.Agent

	if o.killed() {
		o.observe("kill_switch", killSwitchActiveReason, config.ActionBlock, 0, true)
		writeBlockedError(w, blockInfoFor(blockreason.KillSwitchActive, "kill_switch"), "enforced in watch-only: kill switch active", http.StatusServiceUnavailable)
		return
	}
	if err := p.verifyInboundEnvelope(r, cfg); err != nil {
		o.observe(blockLayerMediationEnvelope, inboundEnvelopeFailurePattern(err), config.ActionBlock, 0, true)
		writeBlockedError(w, blockInfoFor(blockreason.EnvelopeVerifyFailed, blockLayerMediationEnvelope), "enforced in watch-only: inbound authentication failed", http.StatusForbidden)
		return
	}
	target, host, port, scanURL, ok := normalizeConnectTarget(r.Host)
	if !ok {
		o.observe("connect", "malformed CONNECT authority", config.ActionBlock, 0, true)
		http.Error(w, "malformed CONNECT authority", http.StatusBadRequest)
		return
	}
	inspection := r.Clone(r.Context())
	parsed, err := http.NewRequestWithContext(r.Context(), http.MethodConnect, scanURL, nil)
	if err != nil {
		o.observe("connect", "malformed CONNECT authority", config.ActionBlock, 0, true)
		http.Error(w, "malformed CONNECT authority", http.StatusBadRequest)
		return
	}
	inspection.URL = parsed.URL
	if !watchAuthorityAllowed(w, inspection, o) {
		return
	}
	if watchRequestDecision(inspection, o) {
		o.receipt(inspection, config.ActionBlock, scannerLabelBodyDLP, "core credential floor enforced")
		writeBlockedError(w, blockInfoFor(blockreason.DLPMatch, scannerLabelBodyDLP), "enforced in watch-only: core credential floor", http.StatusForbidden)
		return
	}
	if !o.receipt(inspection, config.ActionAllow, "watch_only", "CONNECT admitted") && cfg.FlightRecorder.RequireReceipts {
		http.Error(w, "enforced in watch-only: required receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT unavailable", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	reader := buf.Reader
	category := "opaque"
	if cfg.ForwardProxy.SNIVerificationEnabled() || cfg.TLSInterception.Enabled {
		var sniErr error
		reader, _, category, sniErr = verifySNI(reader, conn, host, sniReadTimeoutDefault)
		if sniErr != nil {
			o.observe("sni", "TLS SNI verification refused tunnel", config.ActionBlock, 0, true)
			return
		}
	}
	if cfg.ForwardProxy.SNIRequireTLSEnabled() && (category == sniCategoryNotTLS || category == sniCategoryNoExtension) {
		o.observe("sni", "TLS required for CONNECT", config.ActionBlock, 0, true)
		return
	}
	if cfg.TLSInterception.Enabled && !isPassthrough(host, cfg.TLSInterception.PassthroughDomains) && category != "not_tls" {
		if cache := p.certCachePtr.Load(); cache != nil {
			err := interceptTunnel(r.Context(), wrapBuffered(conn, reader), &InterceptContext{
				TargetHost: host, TargetPort: port,
				Config: cfg, Scanner: sc, CertCache: cache, Logger: p.logger, Metrics: p.metrics, ClientIP: o.ClientIP,
				RequestID: o.RequestID, Agent: agent, ActorAuth: o.ActorAuth, UpstreamRT: p.tlsTransport, SafeDial: p.ssrfSafeDialContext, Proxy: p, KillSwitch: p.ks,
			})
			if err != nil {
				o.observe("tls", "TLS interception could not establish connection", config.ActionBlock, 0, true)
			}
			return
		}
		o.observe("tls", "TLS certificate cache unavailable", config.ActionBlock, 0, true)
		return
	}
	dialCtx := context.WithValue(r.Context(), watchModeContextKey{}, o)
	upstream, err := p.ssrfSafeDialContext(dialCtx, "tcp", target)
	if err != nil {
		o.observe("upstream", "CONNECT upstream unavailable", config.ActionBlock, 0, true)
		return
	}
	defer func() { _ = upstream.Close() }()
	relay := &tunnelRelay{
		client: wrapBuffered(conn, reader), target: upstream,
		idleTimeout: time.Duration(cfg.ForwardProxy.IdleTimeoutSeconds) * time.Second,
		ks:          p.ks, clockStart: time.Now(),
		watchOnly: func() bool { return cfg.WatchOnly },
		observe:   func(reason string, enforced bool) { o.observe("connect", reason, "terminate", 0, enforced) },
	}
	bytes := relay.run()
	o.observe("connect", "opaque CONNECT payload", "uninspected", bytes, false)
	o.receipt(inspection, config.ActionAllow, "watch_only", "opaque CONNECT forwarded")
}
