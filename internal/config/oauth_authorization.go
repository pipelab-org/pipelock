// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "strings"

// NormalizeOAuthAuthorizationEndpoints applies the existing exact HTTPS endpoint
// and expiring scanner-exception contract to native OAuth grants. It returns a
// private copy so scanner construction also fails closed for unvalidated Configs.
func NormalizeOAuthAuthorizationEndpoints(entries []OAuthAuthorizationEndpoint) ([]OAuthAuthorizationEndpoint, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	tuples := oauthAuthorizationTuples(entries)
	if err := validateQueryEntropyParamExclusionsAt(tuples, "fetch_proxy.monitoring.oauth_authorization_endpoints", false); err != nil {
		return nil, err
	}
	out := make([]OAuthAuthorizationEndpoint, len(tuples))
	for i, e := range tuples {
		out[i] = OAuthAuthorizationEndpoint{Host: e.Host, Path: e.Path, Reason: e.Reason, Owner: e.Owner, Expires: e.Expires}
	}
	return out, nil
}

func oauthAuthorizationTuples(entries []OAuthAuthorizationEndpoint) []QueryEntropyParamExclusion {
	if len(entries) == 0 {
		return nil
	}
	out := make([]QueryEntropyParamExclusion, len(entries))
	for i, e := range entries {
		out[i] = QueryEntropyParamExclusion{Scheme: QueryEntropyParamDefaultScheme, Host: e.Host, Path: e.Path, Param: "state", Reason: e.Reason, Owner: e.Owner, Expires: e.Expires}
	}
	return out
}

func canonicalOAuthAuthorizationEndpoints(entries []OAuthAuthorizationEndpoint) []OAuthAuthorizationEndpoint {
	tuples := canonicalQueryEntropyParamExclusions(oauthAuthorizationTuples(entries))
	if len(tuples) == 0 {
		return nil
	}
	out := make([]OAuthAuthorizationEndpoint, len(tuples))
	for i, e := range tuples {
		out[i] = OAuthAuthorizationEndpoint{Host: e.Host, Path: e.Path, Expires: e.Expires}
	}
	return out
}

func validateOAuthAuthorizationEndpoints(c *Config) error {
	entries, err := NormalizeOAuthAuthorizationEndpoints(c.FetchProxy.Monitoring.OAuthAuthorizationEndpoints)
	if err != nil {
		return err
	}
	c.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = entries
	return nil
}

func appendOAuthAuthorizationReloadWarnings(warnings *[]ReloadWarning, old, updated *Config) {
	before := oauthAuthorizationTuples(old.FetchProxy.Monitoring.OAuthAuthorizationEndpoints)
	after := oauthAuthorizationTuples(updated.FetchProxy.Monitoring.OAuthAuthorizationEndpoints)
	if added := queryEntropyParamExclusionsAdded(before, after); len(added) > 0 {
		*warnings = append(*warnings, ReloadWarning{Field: "fetch_proxy.monitoring.oauth_authorization_endpoints", Message: "native OAuth endpoint grants added or extended: " + strings.Join(added, ", ") + "; opaque state/nonce entropy and loopback callback descriptor checks are reduced"})
	}
	if removed := queryEntropyParamExclusionsRemoved(before, after); len(removed) > 0 {
		*warnings = append(*warnings, ReloadWarning{Field: "fetch_proxy.monitoring.oauth_authorization_endpoints", Message: "native OAuth endpoint grants removed: " + strings.Join(removed, ", "), Disposition: ReloadWarningDispositionAdvisory})
	}
}
