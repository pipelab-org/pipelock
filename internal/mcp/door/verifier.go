// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package door verifies external OAuth access tokens for an MCP resource.
package door

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

// Options supplies the pinned configuration and the existing protected dial path.
type Options struct {
	Config      config.MCPDoor
	DialContext func(context.Context, string, string) (net.Conn, error)
	// Transport optionally supplies a protected transport for embedded callers.
	Transport http.RoundTripper
}

// Identity contains only issuer-verified claims, never request metadata.
type Identity struct{ Resource, Issuer, Subject, ClientID string }

// Partition encodes the full identity without delimiter collisions.
func (i Identity) Partition() (provider, subject string) {
	p, _ := json.Marshal([2]string{i.Resource, i.Issuer})
	s, _ := json.Marshal([2]string{i.Subject, i.ClientID})
	return string(p), string(s)
}

// AdmissionError is an admission failure safe to return without token or issuer details.
type AdmissionError struct {
	Status int
	Code   string
}

func (e *AdmissionError) Error() string { return "MCP door admission refused" }

func invalidToken() error {
	return &AdmissionError{Status: http.StatusUnauthorized, Code: "invalid_token"}
}
func unavailable() error { return &AdmissionError{Status: http.StatusServiceUnavailable} }
func malformed() error {
	return &AdmissionError{Status: http.StatusBadRequest, Code: "invalid_request"}
}

// Verifier owns an immutable operator profile. Key/credential files are re-read
// per request so removing them fails closed and replacement supports rotation.
type Verifier struct {
	cfg    config.MCPDoor
	client *http.Client
	now    func() time.Time
}

// New refuses incomplete profiles and unusable verifier material at startup.
func New(opts Options) (*Verifier, error) {
	if !opts.Config.Enabled {
		return nil, nil
	}
	if err := opts.Config.Validate(); err != nil {
		return nil, err
	}
	timeout := opts.Config.TimeoutSeconds
	if timeout == 0 {
		timeout = 10
	} // Same default as the configured MCP dial path.
	v := &Verifier{
		cfg: opts.Config.Clone(), now: time.Now,
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				DialContext:            opts.DialContext,
				TLSHandshakeTimeout:    time.Duration(timeout) * time.Second,
				ResponseHeaderTimeout:  time.Duration(timeout) * time.Second,
				MaxResponseHeaderBytes: int64(transport.MaxLineSize),
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if opts.Transport != nil {
		v.client.Transport = opts.Transport
	}
	if v.cfg.Mode == config.MCPDoorIntrospection && opts.DialContext == nil && opts.Transport == nil {
		return nil, fmt.Errorf("mcp_door introspection requires a protected dial path")
	}
	var err error
	if v.cfg.Mode == config.MCPDoorJWT {
		_, err = v.keys()
	} else {
		_, err = v.secret()
	}
	if err != nil {
		return nil, fmt.Errorf("mcp_door verifier material unavailable")
	}
	return v, nil
}

// Close releases idle introspection connections after the listener stops.
func (v *Verifier) Close() { v.client.CloseIdleConnections() }

// MetadataURL is the RFC 9728 path-based protected-resource metadata URL.
func (v *Verifier) MetadataURL() string {
	u, _ := url.Parse(v.cfg.Audience)
	path, escaped := u.Path, u.EscapedPath()
	// RFC 9728 section 3.1 removes the host's terminating slash, not a
	// trailing slash belonging to a non-root resource path.
	if path == "/" && escaped == "/" {
		path, escaped = "", ""
	}
	u.Path = "/.well-known/oauth-protected-resource" + path
	u.RawPath = "/.well-known/oauth-protected-resource" + escaped
	return u.String()
}

// MetadataPath is the public discovery route served locally by the listener.
func (v *Verifier) MetadataPath() string {
	u, _ := url.Parse(v.MetadataURL())
	return u.Path
}

// WriteMetadata serves only operator-configured resource information.
func (v *Verifier) WriteMetadata(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Resource               string   `json:"resource"`
		AuthorizationServers   []string `json:"authorization_servers"`
		BearerMethodsSupported []string `json:"bearer_methods_supported"`
	}{v.cfg.Audience, []string{v.cfg.Issuer}, []string{"header"}})
}

// WriteFailure owns all OAuth challenges; upstream challenges are never used
// for admission failures.
func (v *Verifier) WriteFailure(w http.ResponseWriter, err error) {
	failure := &AdmissionError{Status: http.StatusServiceUnavailable}
	var typed *AdmissionError
	if errors.As(err, &typed) {
		failure = typed
	}
	if failure.Status == http.StatusUnauthorized || failure.Status == http.StatusBadRequest ||
		failure.Code == "insufficient_scope" {
		challenge := fmt.Sprintf("Bearer resource_metadata=%q", v.MetadataURL())
		if failure.Code != "" {
			challenge += fmt.Sprintf(", error=%q", failure.Code)
		}
		if failure.Code == "insufficient_scope" {
			challenge += fmt.Sprintf(", scope=%q", strings.Join(v.cfg.RequiredScopes, " "))
		}
		w.Header().Set("WWW-Authenticate", challenge)
	}
	http.Error(w, http.StatusText(failure.Status), failure.Status)
}

// Verify authenticates each request, then checks explicit enrollment and scopes.
func (v *Verifier) Verify(r *http.Request) (Identity, error) {
	token, err := bearer(r)
	if err != nil {
		return Identity{}, err
	}
	var claims tokenClaims
	if v.cfg.Mode == config.MCPDoorJWT {
		claims, err = v.jwtClaims(token)
	} else {
		claims, err = v.introspect(r.Context(), token)
	}
	if err != nil {
		return Identity{}, err
	}
	if err := r.Context().Err(); err != nil {
		return Identity{}, unavailable()
	}
	now := v.now()
	if claims.Subject == "" || claims.ClientID == "" || claims.Expiry == nil ||
		!now.Before(claims.Expiry.Time()) || !claims.Audience.Contains(v.cfg.Audience) ||
		(claims.Issuer != "" && claims.Issuer != v.cfg.Issuer) {
		return Identity{}, invalidToken()
	}
	if claims.NotBefore != nil && now.Before(claims.NotBefore.Time()) {
		return Identity{}, invalidToken()
	}
	if claims.IssuedAt != nil && now.Before(claims.IssuedAt.Time()) {
		return Identity{}, invalidToken()
	}
	if len(v.cfg.RequiredScopes) > 0 && claims.Scope == nil {
		return Identity{}, invalidToken()
	}
	admitted := false
	for _, e := range v.cfg.Enrollments {
		if e.Subject == claims.Subject && e.ClientID == claims.ClientID {
			admitted = true
			break
		}
	}
	if !admitted {
		return Identity{}, &AdmissionError{Status: http.StatusForbidden}
	}
	scopes := strings.Split(valueOrEmpty(claims.Scope), " ")
	if valueOrEmpty(claims.Scope) == "" {
		scopes = nil
	}
	if len(v.cfg.RequiredScopes) > 0 {
		for _, scope := range scopes {
			if !config.ValidMCPDoorScope(scope) {
				if v.cfg.Mode == config.MCPDoorIntrospection {
					return Identity{}, unavailable()
				}
				return Identity{}, invalidToken()
			}
		}
	}
	for _, required := range v.cfg.RequiredScopes {
		found := false
		for _, granted := range scopes {
			if granted == required {
				found = true
				break
			}
		}
		if !found {
			return Identity{}, &AdmissionError{Status: http.StatusForbidden, Code: "insufficient_scope"}
		}
	}
	return Identity{Resource: v.cfg.Audience, Issuer: v.cfg.Issuer, Subject: claims.Subject, ClientID: claims.ClientID}, nil
}

func valueOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

type tokenClaims struct {
	jwt.Claims
	ClientID string  `json:"client_id"`
	Scope    *string `json:"scope"`
	Active   *bool   `json:"active"`
}

// bearer implements RFC 6750's header presentation; alternate/ambiguous
// carriers are refused rather than treated as an anonymous request.
func bearer(r *http.Request) (string, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["access_token"]) != 0 || len(r.Header.Values("Proxy-Authorization")) != 0 {
		return "", malformed()
	}
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType == "application/x-www-form-urlencoded" {
		return "", malformed()
	}
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", &AdmissionError{Status: http.StatusUnauthorized}
	}
	if len(values) != 1 {
		return "", malformed()
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", malformed()
	}
	padding := false
	for i, c := range token {
		if i == 0 && c == '=' {
			return "", malformed()
		}
		if c == '=' {
			padding = true
			continue
		}
		switch {
		case padding:
			return "", malformed()
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("-._~+/", c):
			continue
		default:
			return "", malformed()
		}
	}
	return token, nil
}

func (v *Verifier) secret() (string, error) {
	b, err := securefile.Read(v.cfg.ClientSecretFile, securefile.Options{MaxBytes: 8192, DisallowedPerms: 0o077})
	s := strings.TrimSpace(string(b))
	if err != nil || s == "" || strings.ContainsAny(s, "\r\n\x00") {
		return "", unavailable()
	}
	return s, nil
}

func (v *Verifier) introspect(ctx context.Context, token string) (tokenClaims, error) {
	secret, err := v.secret()
	if err != nil {
		return tokenClaims{}, err
	}
	body := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.cfg.IntrospectionURL, strings.NewReader(body.Encode()))
	if err != nil {
		return tokenClaims{}, unavailable()
	}
	// RFC 6749 section 2.3.1 encodes each credential before Basic authentication.
	req.SetBasicAuth(url.QueryEscape(v.cfg.ClientID), url.QueryEscape(secret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return tokenClaims{}, unavailable()
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return tokenClaims{}, unavailable()
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return tokenClaims{}, unavailable()
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(transport.MaxLineSize)+1))
	if err != nil || len(b) > transport.MaxLineSize || jsonscan.RejectNonCanonicalFields(b, tokenClaims{}) != nil {
		return tokenClaims{}, unavailable()
	}
	var claims tokenClaims
	if json.Unmarshal(b, &claims) != nil || claims.Active == nil {
		return tokenClaims{}, unavailable()
	}
	if !*claims.Active {
		return tokenClaims{}, invalidToken()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return tokenClaims{}, unavailable()
	}
	if _, present := fields["iss"]; present && claims.Issuer != v.cfg.Issuer {
		return tokenClaims{}, invalidToken()
	}
	return claims, nil
}

func (v *Verifier) keys() (*jose.JSONWebKeySet, error) {
	b, err := securefile.Read(v.cfg.JWKSFile, securefile.Options{MaxBytes: int64(transport.MaxLineSize), DisallowedPerms: 0o022})
	if err != nil || jsonscan.RejectDuplicateKeys(b) != nil {
		return nil, unavailable()
	}
	var keys jose.JSONWebKeySet
	if json.Unmarshal(b, &keys) != nil || len(keys.Keys) == 0 {
		return nil, unavailable()
	}
	seen := make(map[string]bool)
	for _, key := range keys.Keys {
		public, ok := key.Key.(*rsa.PublicKey)
		// RFC 7518 section 3.3: RS256 keys are at least 2048 bits.
		if !ok || !key.Valid() || !key.IsPublic() || public.N.BitLen() < 2048 ||
			(key.Use != "" && key.Use != "sig") || (key.Algorithm != "" && key.Algorithm != string(jose.RS256)) ||
			seen[key.KeyID] {
			return nil, unavailable()
		}
		seen[key.KeyID] = true
	}
	return &keys, nil
}

func (v *Verifier) jwtClaims(raw string) (tokenClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return tokenClaims{}, invalidToken()
	}
	for _, segment := range parts[:2] {
		b, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil || jsonscan.RejectDuplicateKeys(b) != nil {
			return tokenClaims{}, invalidToken()
		}
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(tok.Headers) != 1 {
		return tokenClaims{}, invalidToken()
	}
	header := tok.Headers[0]
	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if typ != "at+jwt" && typ != "application/at+jwt" {
		return tokenClaims{}, invalidToken()
	}
	keys, err := v.keys()
	if err != nil {
		return tokenClaims{}, err
	}
	matched := keys.Key(header.KeyID)
	if len(matched) == 0 {
		return tokenClaims{}, unavailable()
	}
	var claims tokenClaims
	if tok.Claims(matched[0].Key, &claims) != nil {
		return tokenClaims{}, invalidToken()
	}
	// RFC 9068 section 2.2 requires iss, exp, aud, sub, client_id, iat and jti.
	if claims.Issuer != v.cfg.Issuer || claims.IssuedAt == nil || claims.ID == "" ||
		claims.Expiry == nil || !claims.Expiry.Time().After(claims.IssuedAt.Time()) {
		return tokenClaims{}, invalidToken()
	}
	return claims, nil
}
