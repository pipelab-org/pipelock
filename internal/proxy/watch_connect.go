// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func (p *Proxy) handleWatchConnect(w http.ResponseWriter, r *http.Request, o watchHTTPOptions) {
	start := time.Now()
	cfg, sc, agent := o.Config, o.Scanner, o.Agent
	o.findings, o.requestFinding = &watchFindingLog{}, new(atomic.Bool)

	if o.killed() {
		o.observe("kill_switch", killSwitchActiveReason, config.ActionBlock, 0, true)
		o.recordRefusal(r, "kill_switch", start)
		writeBlockedError(w, blockInfoFor(blockreason.KillSwitchActive, "kill_switch"), "enforced in watch-only: kill switch active", http.StatusServiceUnavailable)
		return
	}
	if err := p.verifyInboundEnvelope(r, cfg); err != nil {
		o.observe(blockLayerMediationEnvelope, inboundEnvelopeFailurePattern(err), config.ActionBlock, 0, true)
		o.recordRefusal(r, blockLayerMediationEnvelope, start)
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
	if !watchAuthorityAllowed(w, inspection, o, start) {
		return
	}
	adm := watchAdmit(inspection, o)
	if adm.Core {
		o.receipt(inspection, config.ActionBlock, scannerLabelBodyDLP, "core credential floor enforced")
		o.recordRefusal(inspection, scannerLabelBodyDLP, start)
		writeBlockedError(w, blockInfoFor(blockreason.DLPMatch, scannerLabelBodyDLP), "enforced in watch-only: core credential floor", http.StatusForbidden)
		return
	}
	findingsOK := o.confirmFindings(inspection)
	admitted := o.receipt(inspection, config.ActionAllow, "watch_only", "CONNECT admitted")
	if (!admitted || !findingsOK) && cfg.FlightRecorder.RequireReceipts {
		o.recordRefusal(inspection, receiptEmissionFailedLayer, start)
		http.Error(w, "enforced in watch-only: required receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	sem := getTunnelSemaphore()
	if !sem.TryAcquire() {
		writeBlockedError(w, blockInfoFor(blockreason.RateLimit, "tunnel_capacity").WithRequestID(o.RequestID), "too many active tunnels", http.StatusServiceUnavailable)
		return
	}
	defer sem.Release()
	// The scan snapshot of the admitted destination reaches the dial, so a
	// granted hostname that resolves to an internal address is not refused for
	// lack of it.
	dialCtx, cancelDial := context.WithTimeout(watchOutboundContext(r.Context(), o, inspection, adm), time.Duration(cfg.ForwardProxy.MaxTunnelSeconds)*time.Second)
	defer cancelDial()
	upstream, err := p.ssrfSafeDialContext(dialCtx, "tcp", target)
	if err != nil {
		if info, reason, blocked := o.upstreamRefusal(inspection, err); blocked {
			writeBlockedError(w, info, "CONNECT blocked: "+reason, http.StatusForbidden)
		} else {
			o.observe("upstream", "CONNECT upstream unavailable", config.ActionBlock, 0, true)
			http.Error(w, "tunnel dial failed", http.StatusBadGateway)
		}
		return
	}
	defer func() { _ = upstream.Close() }()
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
	stopLicenseClose := context.AfterFunc(r.Context(), func() {
		if errors.Is(context.Cause(r.Context()), errAgentLicenseRevoked) {
			_ = conn.Close()
			_ = upstream.Close()
		}
	})
	defer stopLicenseClose()
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
	if cfg.TLSInterception.Enabled && !isPassthrough(host, cfg.TLSInterception.PassthroughDomains) {
		if cache := p.certCachePtr.Load(); cache != nil {
			_ = upstream.Close()
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
	relay := &tunnelRelay{
		client: wrapBuffered(conn, reader), target: upstream,
		idleTimeout: time.Duration(cfg.ForwardProxy.IdleTimeoutSeconds) * time.Second,
		ks:          p.ks, clockStart: time.Now(),
		watchOnly: func() bool { current := p.CurrentConfig(); return current != nil && current.WatchOnly },
		observe:   func(reason string, enforced bool) { o.observe("connect", reason, "terminate", 0, enforced) },
	}
	bytes := relay.run()
	o.observe("connect", "opaque CONNECT payload", "uninspected", bytes, false)
	o.receipt(inspection, config.ActionAllow, "watch_only", "opaque CONNECT forwarded")
}
