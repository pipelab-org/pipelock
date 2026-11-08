// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const credentialAudienceAnthropicOAuthSurface = "anthropic_oauth_body" // #nosec G101 -- scanner surface identifier, not a credential

// OAuthCredentialAudienceSurface recognizes Claude Code's JSON token refresh
// and revocation requests. The caller supplies the actual HTTP destination,
// method and media type, never values from inside the body. Only the designated
// credential field qualifies; independent and joined remainder views retain DLP.
// Source: Claude Code 2.1.310, documented in claude-code-credentials.md.
func (s *Scanner) OAuthCredentialAudienceSurface(ctx context.Context, body []byte, target, method, contentType string) string {
	surface, _, _ := s.OAuthCredentialAudience(ctx, body, target, method, contentType)
	return surface
}

// OAuthCredentialAudience returns the OAuth surface and, when the body
// qualifies, the designated credential both decoded and as the raw JSON value
// in the body, so callers can keep that one value out of non-credential
// heuristics and blank exactly those bytes when checking the remainder.
func (s *Scanner) OAuthCredentialAudience(ctx context.Context, body []byte, target, method, contentType string) (string, string, []byte) {
	const fallback = "body"
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" || method != http.MethodPost || ctx.Err() != nil {
		return fallback, "", nil
	}
	host, ok := canonicalCredentialAudienceDestination(target)
	u, err := url.Parse(target)
	if !ok || err != nil || host != "platform.claude.com" || u.Scheme != "https" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fallback, "", nil
	}
	var field, discriminator, expected string
	switch u.EscapedPath() {
	case "/v1/oauth/token":
		field, discriminator, expected = "refresh_token", "grant_type", "refresh_token"
	case "/v1/oauth/token/revoke":
		field, discriminator, expected = "token", "token_type_hint", "refresh_token"
	default:
		return fallback, "", nil
	}
	if !json.Valid(body) || jsonscan.RejectDuplicateKeys(body) != nil {
		return fallback, "", nil
	}
	var envelope map[string]json.RawMessage
	var credential, kind string
	if json.Unmarshal(body, &envelope) != nil || !jsonField(envelope, discriminator, &kind) ||
		kind != expected || !jsonField(envelope, field, &credential) || credential == "" {
		return fallback, "", nil
	}
	// Only the compiled built-in pattern metadata can earn this carrier.
	for _, pattern := range s.dlpPatterns {
		if pattern.name != "Anthropic API Key" {
			continue
		}
		start, end, matched := pattern.matchSpan(credential)
		if !matched || start != 0 || end != len(credential) {
			return fallback, "", nil
		}
		if _, allowed := s.credentialAudienceAllows(pattern, target, credentialAudienceAnthropicOAuthSurface); !allowed {
			return fallback, "", nil
		}
		// Blank the credential in the original bytes, as the Discord Gateway
		// carrier does, so the remainder keeps source order. Re-marshaling the
		// map would sort keys and hide a copy split across a value and the
		// next key.
		raw := envelope[field]
		if bytes.Count(body, raw) != 1 {
			return fallback, "", nil
		}
		remaining := bytes.Replace(body, raw, []byte(`""`), 1)
		if gatewayRemainderHasCredential(ctx, remaining, pattern.name, s.ScanTextForDLPQuiet) {
			return fallback, "", nil
		}
		return credentialAudienceAnthropicOAuthSurface, credential, raw
	}
	return fallback, "", nil
}
