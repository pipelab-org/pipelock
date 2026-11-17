// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package door

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

const (
	testResource = "https://resource.example/mcp"
	testIssuer   = "https://issuer.example"
	testClient   = "cloud-client"
)

func testConfig() config.MCPDoor {
	return config.MCPDoor{
		Enabled: true, Issuer: testIssuer, Audience: testResource,
		Mode:           config.MCPDoorJWT,
		Enrollments:    []config.MCPDoorEnrollment{{Subject: "subject", ClientID: testClient}},
		RequiredScopes: []string{"tools:read"},
	}
}

func writeTestFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testKeys(t *testing.T, cfg *config.MCPDoor, keys ...jose.JSONWebKey) {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWKSFile == "" {
		cfg.JWKSFile = filepath.Join(t.TempDir(), "keys.json")
	}
	writeTestFile(t, cfg.JWKSFile, b)
}

func testClaims() map[string]any {
	return map[string]any{
		"iss": testIssuer, "aud": testResource, "sub": "subject", "client_id": testClient,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "jti": "grant-token",
		"scope": "tools:read", "active": true,
	}
}

func signTest(t *testing.T, key *rsa.PrivateKey, claims any, typ string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "pinned"}}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func testRequest(token string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, testResource, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func assertStatus(t *testing.T, v *Verifier, req *http.Request, want int) {
	t.Helper()
	_, err := v.Verify(req)
	if want == http.StatusOK {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	var failure *AdmissionError
	if !errors.As(err, &failure) || failure.Status != want {
		t.Fatalf("Verify status: %v, want %d", err, want)
	}
	w := httptest.NewRecorder()
	v.WriteFailure(w, err)
	if w.Code != want {
		t.Fatalf("response %d, want %d", w.Code, want)
	}
	challenge := w.Header().Get("WWW-Authenticate")
	if want == http.StatusUnauthorized && !strings.Contains(challenge, `Bearer resource_metadata="https://resource.example/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("challenge %q", challenge)
	}
	if req.Header.Get("Authorization") != "" && strings.Contains(w.Body.String(), req.Header.Get("Authorization")) {
		t.Fatal("response exposes token")
	}
}

func TestJWTProfile(t *testing.T) {
	key := testKey(t)
	wrong := testKey(t)
	cfg := testConfig()
	testKeys(t, &cfg, jose.JSONWebKey{Key: &key.PublicKey, KeyID: "pinned", Algorithm: string(jose.RS256), Use: "sig"})
	v, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for _, tt := range []struct {
		name   string
		mutate func(map[string]any)
		status int
	}{
		{"valid", func(map[string]any) {}, 200},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Second).Unix() }, 401},
		{"wrong audience", func(c map[string]any) { c["aud"] = "https://other.example/mcp" }, 401},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://other.example" }, 401},
		{"unenrolled subject", func(c map[string]any) { c["sub"] = "other" }, 403},
		{"unenrolled client", func(c map[string]any) { c["client_id"] = "other" }, 403},
		{"insufficient scope", func(c map[string]any) { c["scope"] = "tools:write" }, 403},
		{"no scope", func(c map[string]any) { delete(c, "scope") }, 401},
		{"malformed scope", func(c map[string]any) { c["scope"] = "tools:read\nextra" }, 401},
		{"not yet valid", func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, 401},
		{"future issued", func(c map[string]any) { c["iat"] = time.Now().Add(time.Minute).Unix() }, 401},
		{"audience array", func(c map[string]any) { c["aud"] = []string{"https://other.example", testResource} }, 200},
		{"invalid audience type", func(c map[string]any) { c["aud"] = 7 }, 401},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := testClaims()
			tt.mutate(c)
			assertStatus(t, v, testRequest(signTest(t, key, c, "at+jwt")), tt.status)
		})
	}
	for _, name := range []string{"iss", "aud", "sub", "client_id", "exp", "iat", "jti"} {
		t.Run("required "+name, func(t *testing.T) {
			c := testClaims()
			delete(c, name)
			assertStatus(t, v, testRequest(signTest(t, key, c, "at+jwt")), 401)
		})
		t.Run("null "+name, func(t *testing.T) {
			c := testClaims()
			c[name] = nil
			assertStatus(t, v, testRequest(signTest(t, key, c, "at+jwt")), 401)
		})
	}
	assertStatus(t, v, testRequest(signTest(t, wrong, testClaims(), "at+jwt")), 401)
	assertStatus(t, v, testRequest(signTest(t, key, testClaims(), "JWT")), 401)
	assertStatus(t, v, testRequest(signTest(t, key, testClaims(), "application/at+jwt")), 200)
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte("{}")) + "."
	assertStatus(t, v, testRequest(none), 401)
	for _, raw := range []string{"bad", "a.b.c", base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","alg":"none"}`)) + ".e30.signature", "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"a","sub":"b"}`)) + ".signature"} {
		assertStatus(t, v, testRequest(raw), 401)
	}
	token := signTest(t, key, testClaims(), "at+jwt")
	testKeys(t, &cfg, jose.JSONWebKey{Key: &key.PublicKey, KeyID: "rotated"})
	assertStatus(t, v, testRequest(token), 503)
	writeTestFile(t, cfg.JWKSFile, []byte("{}"))
	assertStatus(t, v, testRequest(token), 503)
	if err := os.Remove(cfg.JWKSFile); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, v, testRequest(token), 503)
}

func TestPresentation(t *testing.T) {
	key := testKey(t)
	cfg := testConfig()
	testKeys(t, &cfg, jose.JSONWebKey{Key: &key.PublicKey, KeyID: "pinned"})
	v, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	token := signTest(t, key, testClaims(), "at+jwt")
	for _, tt := range []struct {
		name   string
		modify func(*http.Request)
		status int
	}{
		{"missing", func(r *http.Request) { r.Header.Del("Authorization") }, 401},
		{"query", func(r *http.Request) { r.URL.RawQuery = "access_token=" + url.QueryEscape(token) }, 400},
		{"query empty", func(r *http.Request) { r.URL.RawQuery = "access_token=" }, 400},
		{"bad query", func(r *http.Request) { r.URL.RawQuery = "%zz" }, 400},
		{"duplicate header", func(r *http.Request) { r.Header.Add("Authorization", "Bearer other") }, 400},
		{"proxy header", func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer other") }, 400},
		{"basic", func(r *http.Request) { r.Header.Set("Authorization", "Basic abc") }, 400},
		{"empty", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }, 400},
		{"spaces", func(r *http.Request) { r.Header.Set("Authorization", "Bearer  abc") }, 400},
		{"comma", func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc,def") }, 400},
		{"padding", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ab=c") }, 400},
		{"form", func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, 400},
		{"forged metadata", func(r *http.Request) { r.Header.Set("X-Client-ID", "other"); r.Header.Set("X-Subject", "other") }, 200},
	} {
		t.Run(tt.name, func(t *testing.T) { r := testRequest(token); tt.modify(r); assertStatus(t, v, r, tt.status) })
	}
	r := testRequest(token)
	r.Header.Set("Authorization", "bearer "+token)
	assertStatus(t, v, r, 200)
	// Expiry is checked on every request; an accepted token is not cached.
	v.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	assertStatus(t, v, testRequest(token), 401)
}

func TestIntrospection(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "secret")
	writeTestFile(t, secretPath, []byte("fixture-secret"))
	for _, tt := range []struct {
		name   string
		body   func() string
		status int
	}{
		{"valid", func() string { b, _ := json.Marshal(testClaims()); return string(b) }, 200},
		{"endpoint bound issuer", func() string { c := testClaims(); delete(c, "iss"); b, _ := json.Marshal(c); return string(b) }, 200},
		{"inactive", func() string { return `{"active":false}` }, 401},
		{"missing active", func() string { return "{}" }, 503},
		{"bad active", func() string { return `{"active":"true"}` }, 503},
		{"malformed", func() string { return "{" }, 503},
		{"duplicate", func() string { return `{"active":true,"active":false}` }, 503},
		{"wrong audience", func() string {
			c := testClaims()
			c["aud"] = "https://other.example"
			b, _ := json.Marshal(c)
			return string(b)
		}, 401},
		{"wrong issuer", func() string {
			c := testClaims()
			c["iss"] = "https://other.example"
			b, _ := json.Marshal(c)
			return string(b)
		}, 401},
		{"expired", func() string {
			c := testClaims()
			c["exp"] = time.Now().Add(-time.Second).Unix()
			b, _ := json.Marshal(c)
			return string(b)
		}, 401},
		{"incomplete", func() string { return `{"active":true}` }, 401},
		{"unenrolled", func() string { c := testClaims(); c["sub"] = "other"; b, _ := json.Marshal(c); return string(b) }, 403},
		{"scope denied", func() string {
			c := testClaims()
			c["scope"] = "tools:write"
			b, _ := json.Marshal(c)
			return string(b)
		}, 403},
		{"null", func() string { return "null" }, 503},
		{"array", func() string { return "[]" }, 503},
		{"oversized", func() string { return strings.Repeat(" ", transport.MaxLineSize+1) }, 503},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id, secret, ok := r.BasicAuth()
				if !ok || id != "verifier-client" || secret != "fixture-secret" {
					t.Error("incorrect verifier authentication")
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.Form.Get("token") != "opaque" || r.Form.Get("token_type_hint") != "access_token" {
					t.Error("incorrect introspection form")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tt.body())
			}))
			defer srv.Close()
			cfg := testConfig()
			cfg.Mode = config.MCPDoorIntrospection
			cfg.IntrospectionURL = srv.URL
			cfg.ClientID = "verifier-client"
			cfg.ClientSecretFile = secretPath
			v, err := New(Options{Config: cfg, Transport: srv.Client().Transport})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			assertStatus(t, v, testRequest("opaque"), tt.status)
		})
	}
}

func TestVerifierAvailability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	writeTestFile(t, path, []byte("fixture-secret"))
	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError, http.StatusFound, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "https://attacker.example")
				w.WriteHeader(status)
			}))
			defer srv.Close()
			cfg := testConfig()
			cfg.Mode = config.MCPDoorIntrospection
			cfg.IntrospectionURL = srv.URL
			cfg.ClientID = "verifier"
			cfg.ClientSecretFile = path
			v, err := New(Options{Config: cfg, Transport: srv.Client().Transport})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			assertStatus(t, v, testRequest("opaque"), 503)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			assertStatus(t, v, testRequest("opaque").WithContext(ctx), 503)
		})
	}
	// A real verifier timeout is different from inactive/expired evidence.
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	cfg := testConfig()
	cfg.Mode = config.MCPDoorIntrospection
	cfg.IntrospectionURL = srv.URL
	cfg.ClientID = "verifier"
	cfg.ClientSecretFile = path
	cfg.TimeoutSeconds = 1
	v, err := New(Options{Config: cfg, Transport: srv.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	assertStatus(t, v, testRequest("opaque"), 503)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, v, testRequest("opaque"), 503)
}

func TestVerifierStartupAndDiscovery(t *testing.T) {
	if (&AdmissionError{}).Error() != "MCP door admission refused" {
		t.Fatal("unsafe admission error text")
	}
	if v, err := New(Options{}); err != nil || v != nil {
		t.Fatal("disabled door changed behavior")
	}
	cfg := testConfig()
	if _, err := New(Options{Config: cfg}); err == nil {
		t.Fatal("incomplete profile accepted")
	}
	cfg.JWKSFile = filepath.Join(t.TempDir(), "missing")
	if _, err := New(Options{Config: cfg}); err == nil {
		t.Fatal("missing keys accepted")
	}
	key := testKey(t)
	for _, keys := range [][]jose.JSONWebKey{
		{},
		{{Key: key, KeyID: "private"}},
		{{Key: &key.PublicKey, Use: "enc"}},
		{{Key: &key.PublicKey, Algorithm: "HS256"}},
		{{Key: &key.PublicKey, KeyID: "duplicate"}, {Key: &key.PublicKey, KeyID: "duplicate"}},
	} {
		testKeys(t, &cfg, keys...)
		if _, err := New(Options{Config: cfg}); err == nil {
			t.Fatal("invalid key set accepted")
		}
	}
	testKeys(t, &cfg, jose.JSONWebKey{Key: &key.PublicKey, KeyID: "pinned"})
	v, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	w := httptest.NewRecorder()
	v.WriteMetadata(w)
	var metadata map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["resource"] != testResource || v.MetadataPath() != "/.well-known/oauth-protected-resource/mcp" {
		t.Fatal(metadata)
	}
	w = httptest.NewRecorder()
	v.WriteFailure(w, errors.New("private details"))
	if w.Code != 503 || strings.Contains(w.Body.String(), "private details") {
		t.Fatal("unsafe error response")
	}
	// Identity tuple encoding is unambiguous, and token refresh is not a new identity.
	a, b := (Identity{Resource: "a", Issuer: "b", Subject: "c", ClientID: "d"}).Partition()
	x, y := (Identity{Resource: "a", Issuer: "b", Subject: "c/d", ClientID: ""}).Partition()
	if a == x && b == y {
		t.Fatal("identity collision")
	}
	cfg.Mode = config.MCPDoorIntrospection
	cfg.JWKSFile = ""
	cfg.IntrospectionURL = "https://issuer.example/introspect"
	cfg.ClientID = "verifier"
	cfg.ClientSecretFile = filepath.Join(t.TempDir(), "missing")
	if _, err := New(Options{Config: cfg}); err == nil {
		t.Fatal("unprotected verifier dial accepted")
	}
	if _, err := New(Options{Config: cfg, Transport: http.DefaultTransport}); err == nil {
		t.Fatal("missing verifier credential accepted")
	}
}

func TestIntrospectionRevocation(t *testing.T) {
	var active atomic.Bool
	active.Store(true)
	var checks atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		checks.Add(1)
		c := testClaims()
		c["active"] = active.Load()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c)
	}))
	defer srv.Close()
	cfg := testConfig()
	cfg.Mode = config.MCPDoorIntrospection
	cfg.ClientID = "verifier"
	cfg.ClientSecretFile = filepath.Join(t.TempDir(), "secret")
	cfg.IntrospectionURL = srv.URL
	writeTestFile(t, cfg.ClientSecretFile, []byte("fixture-secret"))
	v, err := New(Options{Config: cfg, Transport: srv.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	assertStatus(t, v, testRequest("same-token"), http.StatusOK)
	active.Store(false)
	assertStatus(t, v, testRequest("same-token"), http.StatusUnauthorized)
	if checks.Load() != 2 {
		t.Fatal("introspection result was cached")
	}
	active.Store(true)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() { assertStatus(t, v, testRequest("same-token"), http.StatusOK) })
	}
	wg.Wait()
	if checks.Load() != 6 {
		t.Fatal("concurrent requests reused authorization evidence")
	}
}

func TestJWTRequestCancellationAndOptionalScope(t *testing.T) {
	key := testKey(t)
	cfg := testConfig()
	cfg.RequiredScopes = nil
	testKeys(t, &cfg, jose.JSONWebKey{Key: &key.PublicKey, KeyID: "pinned"})
	v, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	c := testClaims()
	delete(c, "scope")
	token := signTest(t, key, c, "at+jwt")
	assertStatus(t, v, testRequest(token), http.StatusOK)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	assertStatus(t, v, testRequest(token).WithContext(ctx), http.StatusServiceUnavailable)
	// An immutable constructor snapshot must survive a caller mutating its input.
	cfg.Enrollments[0].Subject = "other"
	assertStatus(t, v, testRequest(token), http.StatusOK)
	assertStatus(t, v, testRequest("=invalid"), http.StatusBadRequest)
}

func TestIntrospectionRequiredEvidence(t *testing.T) {
	var response atomic.Value
	response.Store([]byte("{}"))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response.Load().([]byte))
	}))
	defer srv.Close()
	cfg := testConfig()
	cfg.Mode = config.MCPDoorIntrospection
	cfg.ClientID = "verifier"
	cfg.IntrospectionURL = srv.URL
	cfg.ClientSecretFile = filepath.Join(t.TempDir(), "secret")
	writeTestFile(t, cfg.ClientSecretFile, []byte("fixture-secret"))
	v, err := New(Options{Config: cfg, Transport: srv.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for _, field := range []string{"aud", "sub", "client_id", "exp", "scope"} {
		t.Run(field, func(t *testing.T) {
			c := testClaims()
			delete(c, field)
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			response.Store(b)
			assertStatus(t, v, testRequest("opaque"), http.StatusUnauthorized)
		})
	}
	for _, tc := range []struct {
		name   string
		value  any
		field  string
		status int
	}{
		{"empty issuer", "", "iss", http.StatusUnauthorized},
		{"null issuer", nil, "iss", http.StatusUnauthorized},
		{"bad scope", "tools:read\nextra", "scope", http.StatusServiceUnavailable},
		{"bad expiry", "future", "exp", http.StatusServiceUnavailable},
		{"missing grant scope", "", "scope", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClaims()
			c[tc.field] = tc.value
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			response.Store(b)
			assertStatus(t, v, testRequest("opaque"), tc.status)
		})
	}
}

func TestMetadataResourcePaths(t *testing.T) {
	for _, tc := range []struct{ resource, metadata string }{
		{"https://resource.example", "https://resource.example/.well-known/oauth-protected-resource"},
		{"https://resource.example/", "https://resource.example/.well-known/oauth-protected-resource"},
		{"https://resource.example/a%2Fb", "https://resource.example/.well-known/oauth-protected-resource/a%2Fb"},
	} {
		v := &Verifier{cfg: config.MCPDoor{Audience: tc.resource}}
		if v.MetadataURL() != tc.metadata {
			t.Fatalf("metadata URL %q want %q", v.MetadataURL(), tc.metadata)
		}
	}
}

func TestVerifierCanonicalClaims(t *testing.T) {
	key := testKey(t)
	cfg := testConfig()
	testKeys(t, &cfg, jose.JSONWebKey{Key: &key.PublicKey, KeyID: "pinned"})
	jwtVerifier, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	defer jwtVerifier.Close()
	var response atomic.Value
	response.Store([]byte("{}"))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response.Load().([]byte))
	}))
	defer srv.Close()
	cfg.Mode = config.MCPDoorIntrospection
	cfg.JWKSFile = ""
	cfg.ClientID = "verifier"
	cfg.IntrospectionURL = srv.URL
	cfg.ClientSecretFile = filepath.Join(t.TempDir(), "secret")
	writeTestFile(t, cfg.ClientSecretFile, []byte("fixture-secret"))
	introspectionVerifier, err := New(Options{Config: cfg, Transport: srv.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	defer introspectionVerifier.Close()
	for _, field := range []string{"iss", "aud", "sub", "client_id", "exp", "scope"} {
		t.Run(field, func(t *testing.T) {
			c := testClaims()
			c[strings.ToUpper(field)] = c[field]
			delete(c, field)
			assertStatus(t, jwtVerifier, testRequest(signTest(t, key, c, "at+jwt")), http.StatusUnauthorized)
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			response.Store(b)
			assertStatus(t, introspectionVerifier, testRequest("opaque"), http.StatusServiceUnavailable)
		})
	}
}
