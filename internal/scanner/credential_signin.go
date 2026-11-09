// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// signInBearerRoute is one provider API that accepts a sign-in access token,
// a JWT, as the Authorization bearer.
type signInBearerRoute struct {
	host     string
	prefix   string
	issuer   string
	clientID string
}

// signInBearerRoutes are the coding clients that sign in with OAuth and send
// the resulting JWT access token to their vendor's own API. Sources:
//   - Codex CLI signed in with ChatGPT, openai/codex at rust-v0.167.0:
//     codex-rs/login/src/server.rs DEFAULT_ISSUER, codex-rs/login/src/auth/manager.rs
//     CLIENT_ID, and the https://chatgpt.com/backend-api/ base URL in
//     codex-rs/cloud-config/src/bundle_loader.rs.
//     https://github.com/openai/codex
//   - The xAI Grok CLI OAuth client, router-for-me/CLIProxyAPI at v8.0.51:
//     internal/auth/xai/types.go Issuer, ClientID, DefaultAPIBaseURL and
//     CLIChatProxyBaseURL.
//     https://github.com/router-for-me/CLIProxyAPI
//
// The proxy cannot verify the token's signature. A token earns a route only
// when its own iss and client_id claims name that provider and client, so a
// JWT whose claims name another issuer or client keeps the block. A token
// from another issuer that copies these claims passes, but it can reach only
// the route host and path those claims name. The registry bearer rule makes
// the same trade.
var signInBearerRoutes = []signInBearerRoute{
	{host: "chatgpt.com", prefix: "/backend-api", issuer: "https://auth.openai.com", clientID: "app_EMoamEEZ73f0CkXaXp7hrann"},
	{host: "api.x.ai", prefix: "/v1", issuer: "https://auth.x.ai", clientID: "b1a00492-073a-47ea-816f-4c329264a828"},
	{host: "cli-chat-proxy.grok.com", prefix: "/v1", issuer: "https://auth.x.ai", clientID: "b1a00492-073a-47ea-816f-4c329264a828"},
}

// signInBearerAllowed accepts a JWT Token match only as the whole
// Authorization Bearer value, over https, at an exact route host and under
// its path prefix, when the token's iss and client_id equal that route's.
func signInBearerAllowed(candidate credentialAudienceCandidate, host, target, surface string) bool {
	// The claims are read from the header value, so they describe the matched
	// token only when the match is in that raw value. The whitespace view only
	// joins fields, and the single-token shape below leaves nothing to join. A
	// token visible only after decoding (percent, base64, hex) could sit beside
	// a genuine sign-in token and borrow its claims.
	if candidate.carrierMask&config.CredentialAudienceCarrierSignInBearer == 0 || surface != CredentialAudienceAuthorizationHeaderSurface ||
		(candidate.encoded != "" && candidate.encoded != "whitespace") {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	path := parsed.EscapedPath()
	if strings.ContainsAny(path, "%\\") || strings.Contains(path, "//") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	token, ok := matchedBearerToken(candidate)
	if !ok {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	var claims map[string]json.RawMessage
	if !decodeJWTSegment(parts[1], 0, &claims) {
		return false
	}
	var issuer, clientID string
	if !jsonField(claims, "iss", &issuer) || !jsonField(claims, "client_id", &clientID) {
		return false
	}
	for _, route := range signInBearerRoutes {
		if host == route.host && strings.HasPrefix(path, route.prefix+"/") &&
			issuer == route.issuer && clientID == route.clientID {
			return true
		}
	}
	return false
}
