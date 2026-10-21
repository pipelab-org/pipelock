//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/luckyPipewrench/pipelock/enterprise/testinit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestIdentityHealthEnterpriseBindings(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Agents = map[string]config.AgentProfile{"bound-profile": {SourceCIDRs: []string{"192.0.2.0/24"}}}
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	ed, err := edition.NewEditionFunc(cfg, sc)
	if err != nil {
		t.Fatal(err)
	}
	defer ed.Close()
	p := &Proxy{}
	p.cfgPtr.Store(cfg)
	p.editionPtr.Store(&editionSnapshot{Edition: ed})
	for _, tt := range []struct {
		name, remote, override string
		want                   envelope.ActorAuth
	}{
		{"source CIDR", "192.0.2.1:43210", "", envelope.ActorAuthBound},
		{"matched header", "198.51.100.1:43210", "", envelope.ActorAuthMatched},
		{"listener binding", "198.51.100.1:43210", "bound-profile", envelope.ActorAuthBound},
		{"unknown listener", "198.51.100.1:43210", "missing-profile", envelope.ActorAuthUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health?identity=1", nil)
			req.RemoteAddr = tt.remote
			req.Header.Set(edition.AgentHeader, "bound-profile")
			if tt.override != "" {
				req = req.WithContext(edition.WithAgentOverride(req.Context(), tt.override))
			}
			got := p.requestIdentityStatus(req)
			if got.ActorAuth != tt.want || got.TrustedForIdentity != tt.want.TrustedForIdentity() {
				t.Fatalf("wrong runtime grade: %+v", got)
			}
		})
	}
	// Revocation must downgrade the real infrastructure mapping before reporting.
	if receiver, ok := ed.(edition.LicenseRevocationReceiver); ok {
		receiver.SetLicenseRevoked(true)
	} else {
		t.Fatal("missing revocation receiver")
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health?identity=1", nil)
	req.RemoteAddr = "192.0.2.1:43210"
	if got := p.requestIdentityStatus(req); got.ActorAuth != envelope.ActorAuthUnknown || got.TrustedForIdentity {
		t.Fatalf("revoked profile trusted: %+v", got)
	}
}
