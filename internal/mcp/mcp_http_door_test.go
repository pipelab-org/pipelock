// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/door"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
)

const (
	doorTestResource = "https://resource.example/mcp"
	doorTestIssuer   = "https://issuer.example"
)

type doorFixture struct {
	verifier *door.Verifier
	token    func(string) string
	keysPath string
	keys     []byte
}

func newDoorFixture(t *testing.T, mode string) doorFixture {
	t.Helper()
	cfg := config.MCPDoor{
		Enabled: true, Mode: mode, Issuer: doorTestIssuer, Audience: doorTestResource,
		Enrollments:    []config.MCPDoorEnrollment{{Subject: "a", ClientID: "cloud"}, {Subject: "b", ClientID: "cloud"}},
		RequiredScopes: []string{"tools:read"},
	}
	claims := func(name string) map[string]any {
		c := map[string]any{
			"active": true, "iss": doorTestIssuer, "aud": doorTestResource, "sub": "a", "client_id": "cloud",
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(), "jti": "fixture", "scope": "tools:read",
		}
		switch name {
		case "b":
			c["sub"] = "b"
		case "bad":
			c["active"] = false
		case "incomplete":
			delete(c, "sub")
		case "expired":
			c["exp"] = time.Now().Add(-time.Second).Unix()
		case "wrong-audience":
			c["aud"] = "https://other.example"
		case "wrong-issuer":
			c["iss"] = "https://other.example"
		case "unenrolled":
			c["client_id"] = "unknown"
		case "denied":
			c["scope"] = "tools:write"
		}
		return c
	}
	if mode == config.MCPDoorIntrospection {
		cfg.TimeoutSeconds = 1
		cfg.ClientID = "verifier"
		cfg.ClientSecretFile = filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(cfg.ClientSecretFile, []byte("fixture-secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			token := r.Form.Get("token")
			if token == "timeout" {
				select {
				case <-r.Context().Done():
				case <-t.Context().Done():
				}
				return
			}
			if token == "unavailable" {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if token == "bad-response" {
				_, _ = io.WriteString(w, "{")
				return
			}
			_ = json.NewEncoder(w).Encode(claims(token))
		}))
		t.Cleanup(srv.Close)
		cfg.IntrospectionURL = srv.URL
		v, err := door.New(door.Options{Config: cfg, Transport: srv.Client().Transport})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(v.Close)
		return doorFixture{verifier: v, token: func(s string) string { return s }, keysPath: cfg.ClientSecretFile, keys: []byte("fixture-secret")}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "pinned"}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg.JWKSFile = filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(cfg.JWKSFile, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := door.New(door.Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return doorFixture{verifier: v, keysPath: cfg.JWKSFile, keys: keys, token: func(name string) string {
		if name == "bad" {
			return "invalid.jwt.token"
		}
		if name == "none" {
			return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`)) + ".e30."
		}
		signingKey := key
		if name == "wrong-key" {
			signingKey = other
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: signingKey, KeyID: "pinned"}}, (&jose.SignerOptions{}).WithType("at+jwt"))
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(claims(name))
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(body)
		if err != nil {
			t.Fatal(err)
		}
		token, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}}
}

func doorRPC(t *testing.T, base, method, token string, body []byte, modify func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, base+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", currentMCPVersion)
	frame := ParseMCPFrame(body)
	if method == http.MethodPost {
		req.Header.Set("Mcp-Method", frame.Method)
		if frame.RoutingName != "" {
			req.Header.Set("Mcp-Name", frame.RoutingName)
		}
	}
	if modify != nil {
		modify(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHTTPListener_DoorDenials(t *testing.T) {
	for _, mode := range []string{config.MCPDoorJWT, config.MCPDoorIntrospection} {
		t.Run(mode, func(t *testing.T) {
			f := newDoorFixture(t, mode)
			var dials atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			defer upstream.Close()
			opts := MCPProxyOpts{
				ListenerDoor: f.verifier, Scanner: testScannerForHTTP(t),
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dials.Add(1)
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
			}
			base, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			cases := []struct {
				name, token string
				status      int
				modify      func(*http.Request)
			}{
				{"bad", "bad", 401, nil},
				{"incomplete", "incomplete", 401, nil},
				{"expired", "expired", 401, nil},
				{"wrong audience", "wrong-audience", 401, nil},
				{"wrong issuer", "wrong-issuer", 401, nil},
				{"unenrolled", "unenrolled", 403, nil},
				{"denied scope", "denied", 403, nil},
				{"missing", "a", 401, func(r *http.Request) { r.Header.Del("Authorization") }},
				{"malformed", "a", 400, func(r *http.Request) { r.Header.Add("Authorization", "Bearer other") }},
				{"query token", "a", 400, func(r *http.Request) { r.URL.RawQuery = "access_token=other" }},
				{"query only", "a", 400, func(r *http.Request) { r.Header.Del("Authorization"); r.URL.RawQuery = "access_token=other" }},
				{"static proxy bearer", "a", 400, func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer other") }},
			}
			if mode == config.MCPDoorJWT {
				cases = append(cases, struct {
					name, token string
					status      int
					modify      func(*http.Request)
				}{"unsigned", "none", 401, nil},
					struct {
						name, token string
						status      int
						modify      func(*http.Request)
					}{"wrong key", "wrong-key", 401, nil})
			} else {
				cases = append(cases, struct {
					name, token string
					status      int
					modify      func(*http.Request)
				}{"unavailable", "unavailable", 503, nil},
					struct {
						name, token string
						status      int
						modify      func(*http.Request)
					}{"bad response", "bad-response", 503, nil})
			}
			if mode == config.MCPDoorIntrospection {
				cases = append(cases, struct {
					name, token string
					status      int
					modify      func(*http.Request)
				}{"timeout", "timeout", http.StatusServiceUnavailable, nil})
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
						resp := doorRPC(t, base, method, f.token(tc.token), principalControlToolsList(1), tc.modify)
						defer func() { _ = resp.Body.Close() }()
						if resp.StatusCode != tc.status {
							b, _ := io.ReadAll(resp.Body)
							t.Fatalf("%s status %d want %d: %s", method, resp.StatusCode, tc.status, b)
						}
						if tc.status == 401 && !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Bearer resource_metadata=") {
							t.Fatal("missing local challenge")
						}
						if resp.Header.Get("Proxy-Authenticate") != "" {
							t.Fatal("proxy challenge used for OAuth")
						}
						if dials.Load() != 0 {
							t.Fatalf("denial dialed upstream %d times", dials.Load())
						}
					}
				})
			}
			{
				if err := os.Remove(f.keysPath); err != nil {
					t.Fatal(err)
				}
				resp := doorRPC(t, base, http.MethodPost, f.token("a"), principalControlToolsList(1), nil)
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusServiceUnavailable || dials.Load() != 0 {
					t.Fatal("missing verifier material did not fail closed")
				}
				if err := os.WriteFile(f.keysPath, f.keys, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestHTTPListener_DoorPrincipalIsolation(t *testing.T) {
	for _, mode := range []string{config.MCPDoorJWT, config.MCPDoorIntrospection} {
		t.Run(mode, func(t *testing.T) {
			f := newDoorFixture(t, mode)
			upstream, calls := principalStateUpstream(t)
			opts := principalStateOpts(t, "")
			opts.ListenerDoor = f.verifier
			base, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			request := func(id int, tool, subject string) string {
				body := principalControlToolCall(id, tool, `{"client_id":"forged","subject":"b"}`)
				resp := doorRPC(t, base, http.MethodPost, f.token(subject), body, func(r *http.Request) {
					r.Header.Set("X-Client-ID", "forged")
					r.Header.Set("X-Subject", "b")
					r.Header.Set("Mcp-Session-Id", "shared-client-session")
				})
				defer func() { _ = resp.Body.Close() }()
				b, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status %d: %s", resp.StatusCode, b)
				}
				return string(b)
			}
			if b := request(1, "read_file", "a"); strings.Contains(b, "chain pattern") {
				t.Fatal(b)
			}
			if b := request(2, "bash_exec", "b"); strings.Contains(b, "chain pattern") {
				t.Fatalf("subject b inherited state: %s", b)
			}
			if b := request(3, "bash_exec", "a"); !strings.Contains(b, "chain pattern") {
				t.Fatalf("subject a lost state through forged identifiers: %s", b)
			}
			if calls.Load() != 2 {
				t.Fatalf("calls %d want 2", calls.Load())
			}
		})
	}
}

func TestHTTPListener_DoorCredentialConsumptionAndDiscovery(t *testing.T) {
	for _, mode := range []string{config.MCPDoorJWT, config.MCPDoorIntrospection} {
		t.Run(mode, func(t *testing.T) {
			f := newDoorFixture(t, mode)
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" {
					t.Error("door credential forwarded upstream")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
			}))
			defer upstream.Close()
			base, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{ListenerDoor: f.verifier, Scanner: testScannerForHTTP(t), ListenerAllowedOrigins: []string{doorTestOrigin}})
			resp := doorRPC(t, base, http.MethodPost, f.token("a"), principalControlToolsList(1), nil)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK || calls.Load() != 1 {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("valid admission: %d %s", resp.StatusCode, b)
			}
			metadataReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+f.verifier.MetadataPath(), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err = http.DefaultClient.Do(metadataReq)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), doorTestResource) || calls.Load() != 1 {
				t.Fatalf("metadata: %d %s", resp.StatusCode, b)
			}
			assertDoorCORS(t, base, f)
		})
	}
}

const doorTestOrigin = "https://client.example"

// assertDoorCORS checks that an allowed browser origin can read the public
// metadata and the OAuth challenge, and that other origins are refused.
func assertDoorCORS(t *testing.T, base string, f doorFixture) {
	t.Helper()
	get := func(origin string) *http.Response {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+f.verifier.MetadataPath(), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", origin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	allowed := get(doorTestOrigin)
	body, err := io.ReadAll(allowed.Body)
	_ = allowed.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if allowed.StatusCode != http.StatusOK || allowed.Header.Get("Access-Control-Allow-Origin") != doorTestOrigin || !strings.Contains(string(body), doorTestResource) {
		t.Fatalf("allowed-origin metadata: %d acao=%q %s", allowed.StatusCode, allowed.Header.Get("Access-Control-Allow-Origin"), body)
	}
	denied := get("https://other.example")
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden || denied.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed-origin metadata: %d", denied.StatusCode)
	}
	challenge := doorRPC(t, base, http.MethodPost, f.token("expired"), principalControlToolsList(1), func(r *http.Request) {
		r.Header.Set("Origin", doorTestOrigin)
	})
	_ = challenge.Body.Close()
	if challenge.StatusCode != http.StatusUnauthorized || challenge.Header.Get("WWW-Authenticate") == "" ||
		!strings.Contains(challenge.Header.Get("Access-Control-Expose-Headers"), "WWW-Authenticate") {
		t.Fatalf("browser challenge: %d expose=%q", challenge.StatusCode, challenge.Header.Get("Access-Control-Expose-Headers"))
	}
}

// TestHTTPListener_DoorNotificationDenialUnderBlockAll keeps the door's 403
// for a refused notification once adaptive enforcement blocks the session.
func TestHTTPListener_DoorNotificationDenialUnderBlockAll(t *testing.T) {
	f := newDoorFixture(t, config.MCPDoorJWT)
	for _, door := range []bool{false, true} {
		t.Run(fmt.Sprint(door), func(t *testing.T) {
			var dials atomic.Int32
			blockAll := true
			opts := MCPProxyOpts{
				Scanner:  testScannerForHTTP(t),
				InputCfg: newHTTPInputCfg(config.ActionBlock),
				PolicyCfg: &policy.Config{Action: config.ActionBlock, Rules: []*policy.CompiledRule{
					{Name: "restricted-tool", ToolPattern: regexp.MustCompile("^restricted$"), Action: config.ActionBlock},
				}},
				AdaptiveCfg: &config.AdaptiveEnforcement{
					Enabled:             true,
					EscalationThreshold: 1,
					Levels:              config.EscalationLevels{Elevated: config.EscalationActions{BlockAll: &blockAll}},
				},
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					dials.Add(1)
					return nil, errors.New("unexpected upstream dial")
				},
				Store: &principalControlAirlockStore{},
			}
			token := "legacy"
			if door {
				opts.ListenerDoor = f.verifier
				token = f.token("a")
			} else {
				opts.ListenerBearerToken = token
			}
			base, _ := startListenerProxyWithOpts(t, "http://127.0.0.1:1", opts)
			secret := "sk-ant-" + strings.Repeat("x", 25)
			first := doorRPC(t, base, http.MethodPost, token, principalControlToolCall(1, "echo", fmt.Sprintf(`{"value":%q}`, secret)), nil)
			firstBody, _ := io.ReadAll(first.Body)
			_ = first.Body.Close()
			if !strings.Contains(string(firstBody), "session_deny") {
				t.Fatalf("session not escalated to block_all: %d %s", first.StatusCode, firstBody)
			}
			notification := bytes.Replace(principalControlToolCall(2, "restricted", "{}"), []byte(`"id":2,`), nil, 1)
			resp := doorRPC(t, base, http.MethodPost, token, notification, nil)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			want := http.StatusAccepted
			if door {
				want = http.StatusForbidden
			}
			if resp.StatusCode != want || len(body) != 0 || dials.Load() != 0 {
				t.Fatalf("notification under block_all: %d want %d body=%s dials=%d", resp.StatusCode, want, body, dials.Load())
			}
		})
	}
}

// TestDoorPolicyNotificationKeeps403UnderBlockAll drives the adaptive
// projection directly: an escalated session must not turn the door's 403 for a
// refused notification into the 202 used by bearer listeners.
func TestDoorPolicyNotificationKeeps403UnderBlockAll(t *testing.T) {
	f := newDoorFixture(t, config.MCPDoorJWT)
	for _, door := range []bool{false, true} {
		t.Run(fmt.Sprint(door), func(t *testing.T) {
			cfg := adaptiveCfgEnabled()
			cfg.Levels.Elevated.BlockAll = boolPtr(true)
			opts := MCPProxyOpts{Rec: &mockRecorder{level: 1}, AdaptiveCfg: cfg}
			status := http.StatusAccepted
			if door {
				opts.ListenerDoor = f.verifier
				status = http.StatusForbidden
			}
			response := httptest.NewRecorder()
			descriptor := mcpDenialAudit{kind: "policy"}
			w := &mcpListenerDenialWriter{ResponseWriter: response, opts: opts, descriptor: &descriptor, notification: true}
			w.WriteHeader(status)
			if response.Code != status || response.Header().Get(blockreason.HeaderReason) != string(blockreason.EscalationLevel) {
				t.Fatalf("projected notification: %d reason=%q, want %d with the escalation reason", response.Code, response.Header().Get(blockreason.HeaderReason), status)
			}
		})
	}
}

func TestHTTPListener_DoorNonLoopbackAndFallback(t *testing.T) {
	f := newDoorFixture(t, config.MCPDoorJWT)
	for _, tc := range []struct {
		name   string
		modify func(*MCPProxyOpts)
	}{
		{"static token", func(o *MCPProxyOpts) { o.ListenerBearerToken = "fixture" }},
		{"static refresh", func(o *MCPProxyOpts) { o.ListenerBearerTokenFn = func() (string, error) { return "", nil } }},
		{"anonymous", func(o *MCPProxyOpts) { o.ListenerAllowUnauthenticated = true }},
		{"alternate resolver", func(o *MCPProxyOpts) {
			o.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) { return ListenerPrincipal{}, nil }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			opts := MCPProxyOpts{ListenerDoor: f.verifier}
			tc.modify(&opts)
			if err := RunHTTPListenerProxy(t.Context(), ln, "http://127.0.0.1:1", io.Discard, opts); err == nil {
				t.Fatal("door accepted fallback authentication")
			}
		})
	}
	// A real wildcard bind must be admitted solely by the configured door.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPListenerProxy(ctx, ln, "http://127.0.0.1:1", io.Discard, MCPProxyOpts{ListenerDoor: f.verifier})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	base := fmt.Sprintf("http://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)
	waitForHTTPHealth(t, base)
	resp := doorRPC(t, base, http.MethodPost, "invalid", principalControlToolsList(1), nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-loopback status %d", resp.StatusCode)
	}
}

func TestHTTPListener_DoorOffRegression(t *testing.T) {
	upstream, calls := principalStateUpstream(t)
	base, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t), ListenerBearerToken: "fixture"})
	resp := doorRPC(t, base, http.MethodPost, "wrong", principalControlToolsList(1), nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("Proxy-Authenticate") == "" || resp.Header.Get("WWW-Authenticate") != "" || calls.Load() != 0 {
		t.Fatal("door-off static authentication changed")
	}
}

func TestHTTPListener_DoorToolPolicyDenial(t *testing.T) {
	for _, mode := range []string{config.MCPDoorJWT, config.MCPDoorIntrospection} {
		t.Run(mode, func(t *testing.T) {
			f := newDoorFixture(t, mode)
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprint(enabled), func(t *testing.T) {
					var dials atomic.Int32
					opts := MCPProxyOpts{
						Scanner:  testScannerForHTTP(t),
						InputCfg: newHTTPInputCfg(config.ActionBlock),
						PolicyCfg: &policy.Config{Action: config.ActionBlock, Rules: []*policy.CompiledRule{
							{Name: "restricted-tool", ToolPattern: regexp.MustCompile("^restricted$"), Action: config.ActionBlock},
						}},
						DialContext: func(context.Context, string, string) (net.Conn, error) {
							dials.Add(1)
							return nil, errors.New("unexpected upstream dial")
						},
					}
					token := "legacy"
					if enabled {
						opts.ListenerDoor = f.verifier
						token = f.token("a")
					} else {
						opts.ListenerBearerToken = token
					}
					base, _ := startListenerProxyWithOpts(t, "http://127.0.0.1:1", opts)
					resp := doorRPC(t, base, http.MethodPost, token, principalControlToolCall(1, "restricted", "{}"), nil)
					defer func() { _ = resp.Body.Close() }()
					want := http.StatusOK
					if enabled {
						want = http.StatusForbidden
					}
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != want || !strings.Contains(string(body), errPolicyBlocked) || dials.Load() != 0 {
						t.Fatalf("tool denial status=%d want=%d dials=%d body=%s", resp.StatusCode, want, dials.Load(), body)
					}
					notification := bytes.Replace(principalControlToolCall(1, "restricted", "{}"), []byte(`"id":1,`), nil, 1)
					noteResp := doorRPC(t, base, http.MethodPost, token, notification, nil)
					defer func() { _ = noteResp.Body.Close() }()
					noteBody, err := io.ReadAll(noteResp.Body)
					if err != nil {
						t.Fatal(err)
					}
					noteWant := http.StatusAccepted
					if enabled {
						noteWant = http.StatusForbidden
					}
					if noteResp.StatusCode != noteWant || len(noteBody) != 0 || dials.Load() != 0 {
						t.Fatalf("notification denial: %d body=%s dials=%d", noteResp.StatusCode, noteBody, dials.Load())
					}
				})
			}
		})
	}
}
