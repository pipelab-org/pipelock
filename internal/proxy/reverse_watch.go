// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"net/http/httputil"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
)

// serveWatchOnly joins the shared HTTP observation path. The standard reverse
// proxy director adds the configured upstream prefix without cleaning the
// caller's path or replacing the original Accept-Encoding header.
func (rp *ReverseProxyHandler) serveWatchOnly(w http.ResponseWriter, r *http.Request, snap reverseRuntimeSnapshot, identity edition.AgentIdentity, clientIP, requestID string) {
	cfg := snap.cfg
	if err := verifyInboundEnvelope(r, cfg, snap.inboundVerifier); err != nil {
		rp.recordWatch(blockLayerMediationEnvelope, inboundEnvelopeFailurePattern(err), config.ActionBlock, 0, true)
		writeReverseProxyBlock(w, http.StatusForbidden, blockInfoFor(blockreason.EnvelopeVerifyFailed, blockLayerMediationEnvelope).WithRequestID(requestID), "inbound mediation envelope verification failed")
		return
	}
	if gate := evaluateSubmitProfileGate(cfg, r); !gate.Allowed {
		rp.recordWatch(scannerLabelSubmitProfile, gate.Reason, config.ActionBlock, 0, true)
		writeReverseProxyBlock(w, gate.Status, gate.Block.WithRequestID(requestID), gate.Reason)
		return
	}
	req := r.Clone(context.WithValue(r.Context(), ctxKeyReverseEnvelopeCfg, cfg))
	(&httputil.ProxyRequest{In: r, Out: req}).SetURL(rp.upstream)
	req.Host = rp.upstream.Host
	serveWatchHTTP(w, req, watchHTTPOptions{
		Config: cfg, Scanner: snap.sc, Logger: rp.logger, Metrics: rp.metrics,
		Transport: TransportReverse, Upstream: rp.proxy.Transport, Proxy: rp.owner,
		Agent: identity.Name, ActorAuth: identity.Auth, ClientIP: clientIP, RequestID: requestID,
		InboundVerified: true, KillSwitch: rp.ks, MaxResponseBytes: int64(rp.responseScanBodyLimit()),
	})
}

func (rp *ReverseProxyHandler) watchRefusal(cfg *config.Config, refuse bool, scannerName, reason, action string) bool {
	if !refuse || cfg == nil || !cfg.WatchOnly {
		return refuse
	}
	rp.recordWatch(scannerName, reason, action, 0, false)
	return false
}

func (rp *ReverseProxyHandler) recordWatch(scannerName, reason, action string, uninspectedBytes int64, enforced bool) {
	if rp.logger != nil {
		rp.logger.LogWatchOnly(TransportReverse, scannerName, reason, action, uninspectedBytes, enforced)
	}
	if rp.metrics != nil {
		rp.metrics.RecordWatchOnly(TransportReverse, scannerName, action, uninspectedBytes)
	}
}
