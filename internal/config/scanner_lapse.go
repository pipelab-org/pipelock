// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
)

// ScannerExceptionActive reports whether an optional date-only authorization
// is active. Dates include their whole UTC day; malformed dates fail closed.
// Callers with required expiry fields must validate those fields first.
func ScannerExceptionActive(expires string, now time.Time) bool {
	if expires == "" {
		return true
	}
	_, err := time.Parse(time.DateOnly, expires)
	return err == nil && expires >= now.UTC().Format(time.DateOnly)
}

// validateLapsingExpiryDate preserves syntax and the existing maximum horizon,
// while allowing a valid past date to lapse rather than invalidate the file.
// The strict shared validator remains unchanged for other authorizations.
func validateLapsingExpiryDate(field, value string, maximum time.Duration) error {
	if _, err := time.Parse(time.DateOnly, value); err != nil {
		return fmt.Errorf("%s %q must be YYYY-MM-DD: %w", field, value, err)
	}
	if value < todayUTC().Format(time.DateOnly) {
		return nil
	}
	return validateTemporaryExpiryDate(field, value, maximum)
}

func (c *Config) validateScannerExceptions() error {
	if err := validateOAuthAuthorizationEndpoints(c); err != nil {
		return err
	}
	if err := validatePathEntropyExclusions(c.FetchProxy.Monitoring.PathEntropyExclusions); err != nil {
		return err
	}
	if err := validateQueryEntropyParamExclusions(c.FetchProxy.Monitoring.QueryEntropyParamExclusions); err != nil {
		return err
	}
	if err := validateRequestBodyEntropyWarnRoutes(&c.RequestBodyScanning); err != nil {
		return err
	}
	if err := validateRequestBodySigV4CredentialRoutes(&c.RequestBodyScanning); err != nil {
		return err
	}
	if err := validateEntropyHostExclusions("request_body_scanning.content_entropy_exclusions", c.RequestBodyScanning.ContentEntropyExclusions); err != nil {
		return err
	}
	return validateEntropyHostExclusions("websocket_proxy.content_entropy_exclusions", c.WebSocketProxy.ContentEntropyExclusions)
}

// LapsedScannerExceptionWarnings returns retained diagnostics, independently
// of the effective lists and policy hash, just like lapsed containment grants.
func (c *Config) LapsedScannerExceptionWarnings() []Warning {
	return slices.Clone(c.lapsedScannerExceptions)
}

// CopyScannerExceptionDiagnosticsFrom preserves private load diagnostics
// across configuration transformations, including profile YAML round trips.
func (c *Config) CopyScannerExceptionDiagnosticsFrom(src *Config) {
	if src == nil {
		c.lapsedScannerExceptions = nil
		return
	}
	c.lapsedScannerExceptions = src.LapsedScannerExceptionWarnings()
}

// LapseExpiredScannerExceptions validates every declaration before removing
// expired entries. It is atomic, idempotent, and must run on a private candidate
// at Load, startup, or reload before policy identity is computed or published.
func (c *Config) LapseExpiredScannerExceptions(now time.Time) ([]Warning, error) {
	candidate := c.Clone()
	if err := candidate.validateScannerExceptions(); err != nil {
		return nil, err
	}
	candidate.partitionScannerExceptions(now)
	c.FetchProxy.Monitoring.PathEntropyExclusions = candidate.FetchProxy.Monitoring.PathEntropyExclusions
	c.FetchProxy.Monitoring.QueryEntropyParamExclusions = candidate.FetchProxy.Monitoring.QueryEntropyParamExclusions
	c.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = candidate.FetchProxy.Monitoring.OAuthAuthorizationEndpoints
	c.RequestBodyScanning.ContentEntropyWarnRoutes = candidate.RequestBodyScanning.ContentEntropyWarnRoutes
	c.RequestBodyScanning.SigV4CredentialRoutes = candidate.RequestBodyScanning.SigV4CredentialRoutes
	c.RequestBodyScanning.ContentEntropyExclusions = candidate.RequestBodyScanning.ContentEntropyExclusions
	c.WebSocketProxy.ContentEntropyExclusions = candidate.WebSocketProxy.ContentEntropyExclusions
	c.lapsedScannerExceptions = candidate.lapsedScannerExceptions
	c.canonicalHashCache = &canonicalHashCacheHolder{}
	c.canonicalRedactionKeyCache = &canonicalHashCacheHolder{}
	return c.LapsedScannerExceptionWarnings(), nil
}

func partitionScannerExceptions[T any](entries []T, field string, describe func(T) (string, string), now time.Time, warnings *[]Warning) []T {
	if entries == nil {
		return nil
	}
	active := make([]T, 0, len(entries))
	for i, entry := range entries {
		expires, scope := describe(entry)
		if ScannerExceptionActive(expires, now) {
			active = append(active, entry)
			continue
		}
		*warnings = append(*warnings, Warning{
			Field:   fmt.Sprintf("%s[%d]", field, i),
			Message: fmt.Sprintf("scanner exception for %s expired on %s; dropped from the effective set; normal scanning applies; renew or remove the entry", scope, expires),
		})
	}
	return active
}

func (c *Config) partitionScannerExceptions(now time.Time) {
	warnings := c.LapsedScannerExceptionWarnings()
	m := &c.FetchProxy.Monitoring
	hadPaths := len(m.PathEntropyExclusions) > 0
	m.PathEntropyExclusions = partitionScannerExceptions(m.PathEntropyExclusions, "fetch_proxy.monitoring.path_entropy_exclusions", func(e PathEntropyExclusion) (string, string) {
		return e.Expires, e.Scheme + "://" + e.Host + e.PathPrefix
	}, now, &warnings)
	// A nonempty operator list includes shipped routes. Lapsing its final
	// entry must retain those routes, while an explicit [] remains an opt-out
	// even after ApplyDefaults, Clone, or a profile YAML round trip.
	if hadPaths && len(m.PathEntropyExclusions) == 0 {
		m.PathEntropyExclusions = ShippedPathEntropyExclusions()
	}
	m.QueryEntropyParamExclusions = partitionScannerExceptions(m.QueryEntropyParamExclusions, "fetch_proxy.monitoring.query_entropy_param_exclusions", func(e QueryEntropyParamExclusion) (string, string) {
		return e.Expires, e.Scheme + "://" + e.Host + e.Path + "?" + e.Param
	}, now, &warnings)
	m.OAuthAuthorizationEndpoints = partitionScannerExceptions(m.OAuthAuthorizationEndpoints, "fetch_proxy.monitoring.oauth_authorization_endpoints", func(e OAuthAuthorizationEndpoint) (string, string) {
		return e.Expires, "https://" + e.Host + e.Path
	}, now, &warnings)
	r := &c.RequestBodyScanning
	r.ContentEntropyWarnRoutes = partitionScannerExceptions(r.ContentEntropyWarnRoutes, "request_body_scanning.content_entropy_warn_routes", func(e RequestBodyEntropyWarnRoute) (string, string) {
		return e.Expires, e.Host + e.Path + e.PathPrefix + " (owner " + e.Owner + ")"
	}, now, &warnings)
	r.SigV4CredentialRoutes = partitionScannerExceptions(r.SigV4CredentialRoutes, "request_body_scanning.sigv4_credential_routes", func(e RequestBodySigV4CredentialRoute) (string, string) {
		return e.Expires, e.Host + e.Path + " (owner " + e.Owner + ")"
	}, now, &warnings)
	host := func(e EntropyHostExclusion) (string, string) { return e.Expires, e.Host + " (owner " + e.Owner + ")" }
	r.ContentEntropyExclusions = partitionScannerExceptions(r.ContentEntropyExclusions, "request_body_scanning.content_entropy_exclusions", host, now, &warnings)
	c.WebSocketProxy.ContentEntropyExclusions = partitionScannerExceptions(c.WebSocketProxy.ContentEntropyExclusions, "websocket_proxy.content_entropy_exclusions", host, now, &warnings)
	c.lapsedScannerExceptions = warnings
}

func validateScannerExceptionMetadata(field, reason, owner string) error {
	for _, text := range []struct {
		name, value string
		max         int
	}{{"reason", reason, 200}, {"owner", owner, 100}} {
		if len(text.value) > text.max {
			return fmt.Errorf("%s.%s must be %d characters or fewer", field, text.name, text.max)
		}
		if strings.IndexFunc(text.value, unicode.IsControl) >= 0 {
			return fmt.Errorf("%s.%s must not contain control characters", field, text.name)
		}
	}
	return nil
}
