// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxyhealth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// Identity reports the loaded runtime's resolution of the diagnostic request.
// It deliberately excludes names, addresses, credentials and state keys.
type Identity struct {
	RuntimeSource             string             `json:"runtime_source"`
	Available                 bool               `json:"available"`
	ActorAuth                 envelope.ActorAuth `json:"actor_auth"`
	TrustedForIdentity        bool               `json:"trusted_for_identity"`
	DefaultIdentityConfigured bool               `json:"default_identity_configured"`
	BindDefaultAgentIdentity  bool               `json:"bind_default_agent_identity"`
	TLSInterceptionEnabled    bool               `json:"tls_interception_enabled"`
	RequestBodyScanEnabled    bool               `json:"request_body_scan_enabled"`
	ScanHeaders               bool               `json:"scan_headers"`
	IssuerBoundSessionCookies bool               `json:"issuer_bound_session_cookies"`
	IssuerIDEvidenceEligible  bool               `json:"issuer_id_evidence_eligible"`
}

// GetIdentity probes the chosen listener using the supplied client and context.
// Errors omit remote response bodies, URLs and header values.
func GetIdentity(ctx context.Context, client *http.Client, listenerURL, agent string) (*Identity, error) {
	u, err := url.Parse(listenerURL)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("identity URL must be an HTTP(S) listener origin without credentials, path, query or fragment")
	}
	if strings.ContainsAny(agent, "\r\n\x00") {
		return nil, errors.New("invalid identity agent header")
	}
	u.Path, u.RawPath, u.RawQuery = "/health", "", "identity=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("cannot construct identity probe")
	}
	if agent != "" {
		req.Header.Set(edition.AgentHeader, agent)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("identity probe failed; verify listener reachability and TLS trust")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity probe returned HTTP %d", resp.StatusCode)
	}
	// Match CheckLaunch's existing bounded health response contract.
	const maxHealthBytes = 64 << 10
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxHealthBytes+1))
	if err != nil || len(data) > maxHealthBytes {
		return nil, errors.New("identity health response unreadable or too large")
	}
	fields, err := decodeObject(data)
	if err != nil {
		return nil, errors.New("invalid identity health response")
	}
	var health string
	if err := json.Unmarshal(fields["status"], &health); err != nil || health != "healthy" {
		return nil, errors.New("identity runtime is unhealthy or incomplete")
	}
	values, err := decodeObject(fields["identity"])
	if err != nil {
		return nil, errors.New("identity diagnostics missing or malformed; use a supporting Pipelock runtime")
	}
	result := &Identity{}
	if err := json.Unmarshal(values["runtime_source"], &result.RuntimeSource); err != nil || result.RuntimeSource != "loaded-runtime" {
		return nil, errors.New("identity runtime source missing or unsupported")
	}
	var grade string
	if err := json.Unmarshal(values["actor_auth"], &grade); err != nil || string(envelope.NormalizeActorAuth(grade)) != grade {
		return nil, errors.New("identity grade missing or unsupported")
	}
	result.ActorAuth = envelope.NormalizeActorAuth(grade)
	for _, field := range []struct {
		name  string
		value *bool
	}{
		{"available", &result.Available},
		{"trusted_for_identity", &result.TrustedForIdentity},
		{"default_identity_configured", &result.DefaultIdentityConfigured},
		{"bind_default_agent_identity", &result.BindDefaultAgentIdentity},
		{"tls_interception_enabled", &result.TLSInterceptionEnabled},
		{"request_body_scan_enabled", &result.RequestBodyScanEnabled},
		{"scan_headers", &result.ScanHeaders},
		{"issuer_bound_session_cookies", &result.IssuerBoundSessionCookies},
		{"issuer_id_evidence_eligible", &result.IssuerIDEvidenceEligible},
	} {
		raw := values[field.name]
		if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, errors.New("identity diagnostic fields incomplete")
		}
		if err := json.Unmarshal(raw, field.value); err != nil {
			return nil, errors.New("identity diagnostic fields malformed")
		}
	}
	if !result.Available {
		return nil, errors.New("identity runtime resolution unavailable")
	}
	trusted := result.ActorAuth.TrustedForIdentity()
	eligible := trusted && result.TLSInterceptionEnabled && result.RequestBodyScanEnabled && result.ScanHeaders && result.IssuerBoundSessionCookies
	if result.TrustedForIdentity != trusted || result.IssuerIDEvidenceEligible != eligible {
		return nil, errors.New("identity diagnostic trust state inconsistent")
	}
	return result, nil
}
