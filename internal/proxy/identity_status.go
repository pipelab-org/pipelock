// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/proxyhealth"
)

func (p *Proxy) requestIdentityStatus(r *http.Request) *proxyhealth.Identity {
	result := &proxyhealth.Identity{RuntimeSource: "loaded-runtime", ActorAuth: envelope.ActorAuthUnknown}
	// Match production request resolution and pair its effective policy with the
	// same edition under the reload lock. No local config file is loaded here.
	p.reloadMu.RLock()
	defer p.reloadMu.RUnlock()
	if p.cfgPtr.Load() == nil || p.editionPtr.Load() == nil || r.Context().Err() != nil {
		return result
	}
	resolved, id := p.resolveAgentFromRequest(r)
	if resolved == nil || resolved.Config == nil {
		return result
	}
	ctx, release := agentLicenseContext(r.Context(), resolved)
	defer release()
	if ctx.Err() != nil {
		return result
	}
	cfg := resolved.Config
	result.Available = true
	result.ActorAuth = envelope.NormalizeActorAuth(string(id.Auth))
	result.TrustedForIdentity = result.ActorAuth.TrustedForIdentity()
	result.DefaultIdentityConfigured = cfg.DefaultAgentIdentity != ""
	result.BindDefaultAgentIdentity = cfg.BindDefaultAgentIdentity
	result.TLSInterceptionEnabled = cfg.TLSInterception.Enabled
	result.RequestBodyScanEnabled = cfg.RequestBodyScanning.Enabled
	result.ScanHeaders = cfg.RequestBodyScanning.ScanHeaders
	result.IssuerBoundSessionCookies = cfg.RequestBodyScanning.IssuerBoundSessionCookies
	result.IssuerIDEvidenceEligible = result.TrustedForIdentity && issuerCookieEnabled(cfg)
	return result
}
