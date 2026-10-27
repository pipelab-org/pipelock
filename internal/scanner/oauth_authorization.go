// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

type (
	oauthAuthorizationMethodKey    struct{}
	oauthAuthorizationAllowanceKey struct{}
	oauthAuthorizationPolicyKey    struct{}
)

// WithOAuthAuthorizationMethod supplies the actual upstream request method.
// URL-only scans and non-HTTP transports cannot acquire native OAuth relief.
func WithOAuthAuthorizationMethod(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, oauthAuthorizationMethodKey{}, method)
}

// WithOAuthAuthorizationPolicy intersects a connection-scoped scanner's grant
// with the current policy. A revoked grant must not survive in an old tunnel.
// The Config is an immutable request snapshot; nil fails closed.
func WithOAuthAuthorizationPolicy(ctx context.Context, cfg *config.Config) context.Context {
	return context.WithValue(ctx, oauthAuthorizationPolicyKey{}, cfg)
}

func oauthEndpointPermitted(entries []config.OAuthAuthorizationEndpoint, host, path string, now time.Time) bool {
	for _, e := range entries {
		if e.Host == host && e.Path == path && config.ScannerExceptionActive(e.Expires, now) {
			return true
		}
	}
	return false
}

type oauthAuthorizationAllowance struct {
	state    string
	nonce    string
	redirect *url.URL
}

// nativeOAuthAuthorization requires BOTH operator authority and an unambiguous
// direct authorization-code request. Discovery and PKCE do not prove that an
// agent's opaque state is random. The operator grant accepts that channel.
// RFC 6749 3.1/4.1.1 forbids repeated parameters; RFC 7636 4.2/4.3 defines S256.
// State/nonce have no protocol maximum: the existing full URL limit bounds them.
func (s *Scanner) nativeOAuthAuthorization(ctx context.Context, target *url.URL, now time.Time) *oauthAuthorizationAllowance {
	if method, _ := ctx.Value(oauthAuthorizationMethodKey{}).(string); method != http.MethodGet {
		return nil
	}
	if target == nil || target.Scheme != "https" || target.User != nil || target.Opaque != "" || target.Fragment != "" || !isDefaultEndpointPort(target, "https") {
		return nil
	}
	// Invalid runtime hosts canonicalize to empty and cannot match the
	// nonempty DNS hosts validated at scanner construction.
	host, _ := canonicalQueryEntropyRuntimeHost(target.Hostname())
	if !oauthEndpointPermitted(s.oauthAuthorizationEndpoints, host, target.EscapedPath(), now) {
		return nil
	}
	if live, ok := ctx.Value(oauthAuthorizationPolicyKey{}).(*config.Config); ok {
		if live == nil {
			return nil
		}
		entries, err := config.NormalizeOAuthAuthorizationEndpoints(live.FetchProxy.Monitoring.OAuthAuthorizationEndpoints)
		if err != nil || !oauthEndpointPermitted(entries, host, target.EscapedPath(), now) {
			return nil
		}
	}

	q, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		return nil
	}
	// Empty pairs and semicolon separators have divergent interpretations across
	// servers. ParseQuery rejects semicolons, but silently ignores empty pairs.
	for _, pair := range strings.Split(target.RawQuery, "&") {
		if pair == "" || !strings.Contains(pair, "=") {
			return nil
		}
	}
	for k, values := range q {
		if k == "" || len(values) != 1 {
			return nil
		}
	}
	if q.Get("response_type") != "code" || q.Get("client_id") == "" || q.Get("redirect_uri") == "" || q.Has("request") || q.Has("request_uri") {
		return nil
	}
	if q.Has("code_challenge") || q.Has("code_challenge_method") {
		if !pkceExemptionApplies(q[pkceMethodParam], q[pkceChallengeParam]) || !isPKCES256Challenge(pkceChallengeParam, q.Get(pkceChallengeParam), true) {
			return nil
		}
	} else if q.Get("state") == "" {
		return nil
	}
	rawRedirect := q.Get("redirect_uri")
	redirect, err := url.Parse(rawRedirect)
	if err != nil || !redirect.IsAbs() || redirect.Opaque != "" && redirect.Path == "" || redirect.User != nil || strings.Contains(rawRedirect, "#") || strings.Contains(rawRedirect, `\`) {
		return nil
	}
	// The server returns state to redirect_uri, including on an error redirect
	// that needs no user (RFC 6749 4.1.2.1), and any client registered there
	// can name a remote callback. A delivered redirect to a remote HTTPS
	// callback becomes declared issuer evidence, so relieved values would reach
	// that host. Only a callback that stays on this machine qualifies: a literal
	// HTTP loopback (RFC 8252 7.3) or a private-use scheme, which RFC 8252 7.1
	// requires to be a reverse-order domain name.
	allowance := &oauthAuthorizationAllowance{state: q.Get("state"), nonce: q.Get("nonce")}
	switch {
	case literalOAuthLoopback(redirect):
		allowance.redirect = redirect
	case redirect.Scheme == "http" || redirect.Scheme == "https" || !strings.Contains(redirect.Scheme, "."):
		return nil
	}
	return allowance
}

// literalOAuthLoopback recognizes only the spellings described by RFC 8252
// 7.3/8.3. It never resolves names or canonicalizes alternate numeric forms.
func literalOAuthLoopback(u *url.URL) bool {
	if u.Scheme != "http" || u.User != nil || u.Opaque != "" || u.Fragment != "" || strings.ContainsAny(u.Host, "%\\") {
		return false
	}
	host := u.Hostname()
	switch host {
	case "127.0.0.1", "::1", "localhost":
	default:
		return false
	}
	if _, ok := urlDestination(u, host); !ok {
		return false
	}
	authority := host
	if host == "::1" {
		authority = "[::1]"
	}
	if port := u.Port(); port != "" {
		authority += ":" + port
	}
	return u.Host == authority
}

func nativeOAuthQueryAllowed(ctx context.Context, key, value string) bool {
	allowance, _ := ctx.Value(oauthAuthorizationAllowanceKey{}).(*oauthAuthorizationAllowance)
	if allowance == nil || value == "" {
		return false
	}
	return key == "state" && value == allowance.state || key == "nonce" && value == allowance.nonce
}

// nativeOAuthNestedTarget removes only the validated callback descriptor from
// destination scanning. All content scanners already saw the full URL, including
// callback path/query bytes. Other parameters and URLs nested inside the callback
// remain destination candidates; the callback itself is never fetched here.
func nativeOAuthNestedTarget(ctx context.Context, target *url.URL) *url.URL {
	allowance, _ := ctx.Value(oauthAuthorizationAllowanceKey{}).(*oauthAuthorizationAllowance)
	if allowance == nil || allowance.redirect == nil {
		return target
	}
	copyTarget := *target
	var pairs []string
	for _, pair := range strings.Split(target.RawQuery, "&") {
		key, _, _ := strings.Cut(pair, "=")
		decoded, err := url.QueryUnescape(key)
		if err != nil || decoded != "redirect_uri" {
			pairs = append(pairs, pair)
		}
	}
	// The embedded query is not exempt. Include it as raw query components so
	// URL-shaped keys and values receive the ordinary decoding and SSRF checks.
	if allowance.redirect.RawQuery != "" {
		pairs = append(pairs, allowance.redirect.RawQuery)
	}
	copyTarget.RawQuery = strings.Join(pairs, "&")
	return &copyTarget
}
