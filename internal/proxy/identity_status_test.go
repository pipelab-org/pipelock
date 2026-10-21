// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/proxyhealth"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestIdentityHealthActualGrade(t *testing.T) {
	for _, tt := range []struct {
		name, header, override string
		bind                   bool
		want                   envelope.ActorAuth
	}{
		{"configured default", "", "", false, envelope.ActorAuthConfigDefault},
		{"header does not inherit state trust", "caller-label", "", false, envelope.ActorAuthSelfDeclared},
		{"bound default", "caller-label", "", true, envelope.ActorAuthConfigDefault},
		{"listener binding", "caller-label", edition.ProfileDefault, false, envelope.ActorAuthBound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DefaultAgentIdentity = "operator-label"
			cfg.BindDefaultAgentIdentity = tt.bind
			p := newTestProxyWithConfig(t, cfg)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health?identity=1", nil)
			if tt.header != "" {
				req.Header.Set(edition.AgentHeader, tt.header)
			}
			if tt.override != "" {
				req = req.WithContext(edition.WithAgentOverride(req.Context(), tt.override))
			}
			rec := httptest.NewRecorder()
			p.Handler().ServeHTTP(rec, req)
			var body struct {
				Identity *proxyhealth.Identity `json:"identity"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusOK || body.Identity == nil {
				t.Fatalf("diagnostics unavailable: %d", rec.Code)
			}
			got := body.Identity
			if got.ActorAuth != tt.want || got.TrustedForIdentity != tt.want.TrustedForIdentity() {
				t.Fatalf("identity = %+v", got)
			}
			for _, private := range []string{"operator-label", "caller-label", "listener-profile", "192.0.2.1"} {
				if strings.Contains(rec.Body.String(), private) {
					t.Fatal("private request identity exposed")
				}
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("identity response must not be cached")
			}
		})
	}
}

func TestIdentityHealthOptIn(t *testing.T) {
	p := newTestProxy(t)
	for _, tt := range []struct {
		path, method string
		status       int
		identity     bool
	}{
		{"/health", http.MethodGet, http.StatusOK, false},
		{"/health?identity=1", http.MethodGet, http.StatusOK, true},
		{"/health?identity=0", http.MethodGet, http.StatusBadRequest, false},
		{"/health?identity=1&identity=1", http.MethodGet, http.StatusBadRequest, false},
		{"/health?identity=1&bad=%zz", http.MethodGet, http.StatusBadRequest, false},
		{"/health?identity=1", http.MethodPost, http.StatusMethodNotAllowed, false},
	} {
		t.Run(tt.method+tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			p.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil))
			if rec.Code != tt.status || strings.Contains(rec.Body.String(), `"identity":`) != tt.identity {
				t.Fatalf("unexpected response: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIdentityHealthUnavailable(t *testing.T) {
	p := &Proxy{}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health?identity=1", nil)
	got := p.requestIdentityStatus(req)
	if got.Available || got.ActorAuth != envelope.ActorAuthUnknown || got.IssuerIDEvidenceEligible {
		t.Fatalf("unavailable identity = %+v", got)
	}
	p = newTestProxy(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := p.requestIdentityStatus(req.WithContext(ctx)); got.Available || got.TrustedForIdentity {
		t.Fatal("canceled request acquired trust")
	}
}

func TestIdentityHealthReload(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DefaultAgentIdentity = "operator-label"
	p := newTestProxyWithConfig(t, cfg)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health?identity=1", nil)
	first := p.requestIdentityStatus(req)
	next := cfg.Clone()
	next.DefaultAgentIdentity = ""
	next.RequestBodyScanning.ScanHeaders = !cfg.RequestBodyScanning.ScanHeaders
	sc := scanner.MustNew(next)
	if !p.Reload(next, sc) {
		sc.Close()
		t.Fatal("reload failed")
	}
	got := p.requestIdentityStatus(req)
	if !first.DefaultIdentityConfigured || got.DefaultIdentityConfigured || got.ActorAuth != envelope.ActorAuthSelfDeclared || got.ScanHeaders != next.RequestBodyScanning.ScanHeaders {
		t.Fatalf("stale reload diagnostics: %+v", got)
	}
}

// identityStatusEdition substitutes only the resolver result; the diagnostic
// still exercises production normalization, entitlement and prerequisite checks.
type identityStatusEdition struct {
	edition.Edition
	resolved *edition.ResolvedAgent
	auth     envelope.ActorAuth
}

func (e identityStatusEdition) ResolveAgent(context.Context, *http.Request) (*edition.ResolvedAgent, edition.AgentIdentity) {
	return e.resolved, edition.AgentIdentity{Name: "private-label", Auth: e.auth}
}

func TestIdentityHealthPrerequisites(t *testing.T) {
	for _, tt := range []struct {
		name     string
		auth     envelope.ActorAuth
		disable  string
		eligible bool
	}{
		{"bound", envelope.ActorAuthBound, "", true},
		{"default", envelope.ActorAuthConfigDefault, "", true},
		{"matched", envelope.ActorAuthMatched, "", false},
		{"self declared", envelope.ActorAuthSelfDeclared, "", false},
		{"unknown", envelope.ActorAuthUnknown, "", false},
		{"invalid grade", "invalid", "", false},
		{"TLS off", envelope.ActorAuthBound, "tls", false},
		{"body off", envelope.ActorAuthBound, "body", false},
		{"headers off", envelope.ActorAuthBound, "headers", false},
		{"cookies off", envelope.ActorAuthBound, "cookies", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.DefaultAgentIdentity = "private-label"
			cfg.TLSInterception.Enabled = true
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.ScanHeaders = true
			cfg.RequestBodyScanning.IssuerBoundSessionCookies = true
			switch tt.disable {
			case "tls":
				cfg.TLSInterception.Enabled = false
			case "body":
				cfg.RequestBodyScanning.Enabled = false
			case "headers":
				cfg.RequestBodyScanning.ScanHeaders = false
			case "cookies":
				cfg.RequestBodyScanning.IssuerBoundSessionCookies = false
			}
			p := &Proxy{}
			p.cfgPtr.Store(cfg)
			p.editionPtr.Store(&editionSnapshot{Edition: identityStatusEdition{resolved: &edition.ResolvedAgent{Config: cfg}, auth: tt.auth}})
			got := p.requestIdentityStatus(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health?identity=1", nil))
			if got.IssuerIDEvidenceEligible != tt.eligible || got.ActorAuth != envelope.NormalizeActorAuth(string(tt.auth)) {
				t.Fatalf("wrong diagnostics: %+v", got)
			}
		})
	}
}

func TestIdentityHealthUnavailableResolution(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	for _, tt := range []struct {
		name     string
		resolved *edition.ResolvedAgent
	}{
		{"nil result", nil},
		{"nil config", &edition.ResolvedAgent{}},
		{"revoked", &edition.ResolvedAgent{Config: config.Defaults(), LicenseRevoked: closed}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{}
			p.cfgPtr.Store(config.Defaults())
			p.editionPtr.Store(&editionSnapshot{Edition: identityStatusEdition{resolved: tt.resolved, auth: envelope.ActorAuthBound}})
			got := p.requestIdentityStatus(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health?identity=1", nil))
			if got.Available || got.TrustedForIdentity || got.IssuerIDEvidenceEligible || got.ActorAuth != envelope.ActorAuthUnknown {
				t.Fatalf("invalid resolution acquired trust: %+v", got)
			}
		})
	}
}
