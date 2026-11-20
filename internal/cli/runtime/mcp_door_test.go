// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const doorStaticAuthHeader = "Authorization"

func runtimeDoorIssuer(t *testing.T) (jose.Signer, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "pinned"}}})
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(keyPath, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "pinned"}}, (&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	return signer, keyPath
}

func runtimeDoorToken(t *testing.T, signer jose.Signer, issuer, audience, subject, clientID string) string {
	t.Helper()
	now := time.Now()
	claims, err := json.Marshal(map[string]any{"iss": issuer, "aud": audience, "sub": subject, "client_id": clientID, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(), "jti": "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func runtimeDoorConfig(t *testing.T) (string, string) {
	t.Helper()
	const issuer, audience, subject, clientID = "https://issuer.example", "https://resource.example/mcp", "caller", "cloud"
	signer, keyPath := runtimeDoorIssuer(t)
	raw := fmt.Sprintf("mcp_door:\n  enabled: true\n  issuer: %s\n  audience: %s\n  mode: jwt\n  jwks_file: %q\n  enrollments:\n    - subject: %s\n      client_id: %s\n", issuer, audience, keyPath, subject, clientID)
	return raw, runtimeDoorToken(t, signer, issuer, audience, subject, clientID)
}

func writeDoorConfig(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "door.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type doorListenerReady chan string

func (ready doorListenerReady) Write(p []byte) (int, error) {
	if address, ok := strings.CutPrefix(string(p), "pipelock: MCP reverse proxy listening on "); ok {
		ready <- strings.TrimSpace(address)
	}
	return len(p), nil
}

func startDoorCommand(t *testing.T, configPath, upstream string, flags ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	ready := make(doorListenerReady, 1)
	done := make(chan struct{})
	cmd := McpCmd()
	cmd.SetContext(ctx)
	cmd.SetOut(io.Discard)
	cmd.SetErr(ready)
	cmd.SetArgs(append([]string{"proxy", "--listen", "127.0.0.1:0", "--upstream", upstream, "--config", configPath}, flags...))
	var runErr error
	go func() {
		defer close(done)
		runErr = cmd.Execute()
	}()
	started := false
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
			if started && runErr != nil && !errors.Is(runErr, context.Canceled) {
				t.Errorf("door command stop: %v", runErr)
			}
		case <-time.After(testwait.Deadline(10 * time.Second)):
			t.Error("door command did not stop")
		}
	})
	select {
	case address := <-ready:
		started = true
		return "http://" + address, nil
	case <-done:
		return "", runErr
	case <-time.After(testwait.Deadline(10 * time.Second)):
		t.Fatal("door command neither started nor exited")
		return "", nil
	}
}

func TestMCPDoorRejectsStaticUpstreamAuth(t *testing.T) {
	raw, _ := runtimeDoorConfig(t)
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	const proxyAuthHeader = "Proxy-Authorization"
	const carrier = "PIPELOCK_VSCODE_TEST_DOOR_AUTH"
	value := "Bearer " + "static-fixture"
	t.Setenv(carrier, value)
	sidecar := filepath.Join(t.TempDir(), "headers")
	for _, tc := range []struct {
		name, header, source string
		flags                []string
		urlUser              bool
	}{
		{name: "repeatable flags", header: doorStaticAuthHeader, source: "--header", flags: []string{"--header", "X-Fixture: example", "--header", "aUtHoRiZaTiOn: " + value}},
		{name: "proxy flag", header: proxyAuthHeader, source: "--header", flags: []string{"--header", "proxy-authorization: " + value}},
		{name: "header file", header: doorStaticAuthHeader, source: "--header-file", flags: []string{"--header-file", sidecar}},
		{name: "proxy header file", header: proxyAuthHeader, source: "--header-file", flags: []string{"--header-file", sidecar}},
		{name: "environment carrier", header: doorStaticAuthHeader, source: "--header-carrier", flags: []string{"--header-carrier", "authorization=" + carrier}},
		{name: "proxy environment carrier", header: proxyAuthHeader, source: "--header-carrier", flags: []string{"--header-carrier", "proxy-authorization=" + carrier}},
		{name: "URL credentials", header: doorStaticAuthHeader, source: "--upstream", urlUser: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.source == "--header-file" {
				if err := os.WriteFile(sidecar, []byte(strings.ToLower(tc.header)+": "+value+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			upstreamURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			if tc.urlUser {
				upstreamURL.User = url.UserPassword("account", "static-fixture")
			}
			base, err := startDoorCommand(t, writeDoorConfig(t, raw), upstreamURL.String(), tc.flags...)
			if err == nil {
				t.Fatalf("MCP door started at %s with static upstream %s", base, tc.header)
			}
			msg := err.Error()
			if !strings.Contains(msg, "mcp_door") || !strings.Contains(msg, "static upstream "+tc.header) ||
				!strings.Contains(msg, "remove") || !strings.Contains(msg, tc.source) || strings.Contains(msg, "static-fixture") {
				t.Fatalf("startup error did not identify the conflict and fix without the credential: %v", err)
			}
		})
	}
}

func TestMCPDoorDisabledPermitsStaticUpstreamAuth(t *testing.T) {
	value := "Bearer " + "static-fixture"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(doorStaticAuthHeader) != value {
			t.Error("upstream Authorization changed with the door disabled")
		}
		writeDoorTools(w)
	}))
	defer upstream.Close()
	for _, tc := range []struct{ name, yaml string }{
		{"omitted", "mcp_door: {}\n"},
		{"null", "mcp_door:\n  enabled: null\n"},
		{"blank", "mcp_door:\n  enabled:\n"},
		{"false", "mcp_door:\n  enabled: false\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, err := startDoorCommand(t, writeDoorConfig(t, tc.yaml), upstream.URL, "--header", doorStaticAuthHeader+": "+value)
			if err != nil {
				t.Fatal(err)
			}
			if status, _ := runtimeDoorToolsList(t, t.Context(), base+"/", ""); status != http.StatusOK {
				t.Fatalf("tools/list status = %d, want %d", status, http.StatusOK)
			}
		})
	}
}

func mcpDoorGuideSection(t *testing.T, guide, heading string) string {
	t.Helper()
	_, section, ok := strings.Cut(guide, "\n## "+heading+"\n")
	if !ok {
		t.Fatalf("guide is missing the %s section", heading)
	}
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}
	return section
}

func mcpDoorGuideYAML(t *testing.T, section string) string {
	t.Helper()
	_, yamlBlock, opened := strings.Cut(section, "\n```yaml\n")
	raw, _, closed := strings.Cut(yamlBlock, "\n```\n")
	if !opened || !closed || strings.TrimSpace(raw) == "" {
		t.Fatal("guide section is missing a yaml example")
	}
	return raw
}

func TestMCPDoorGuideRecipe(t *testing.T) {
	guide, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "guides", "mcp-door-recipe.md"))
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	const upstreamUserinfoRefusal = "a username or password in the `--upstream` URL"
	for _, doc := range []struct{ name, body string }{
		{"guide", string(guide)},
		{"configuration", string(configuration)},
	} {
		if !strings.Contains(doc.body, "static upstream `Authorization` and `Proxy-Authorization`") ||
			!strings.Contains(doc.body, "--header-file") || !strings.Contains(doc.body, "--header-carrier") ||
			!strings.Contains(doc.body, upstreamUserinfoRefusal) {
			t.Fatalf("%s dropped the static upstream credential refusal", doc.name)
		}
	}

	jwtSection := mcpDoorGuideSection(t, string(guide), "JWT verification")
	raw := mcpDoorGuideYAML(t, jwtSection)
	const jwksPlaceholder = "/etc/pipelock/issuer-public.jwks.json"
	if !strings.Contains(raw, jwksPlaceholder) {
		t.Fatal("JWT door.yaml example missing from the guide")
	}
	introSection := mcpDoorGuideSection(t, string(guide), "Introspection with Keycloak")
	introRaw := mcpDoorGuideYAML(t, introSection)
	const introspectionClient = "mcp-introspector"
	for _, phrase := range []string{
		"confidential client's client ID is in the access token's `aud` claim",
		"public MCP URL in the introspection response's `aud`",
		"Included Client Audience",
		"Included Custom Audience",
		"custom audience only when the client audience is empty",
		"Add to access token",
		"Add to token introspection",
		"**Included Client Audience** to `" + introspectionClient + "`",
	} {
		if !strings.Contains(introSection, phrase) {
			t.Fatalf("Keycloak section missing %q", phrase)
		}
	}
	if strings.Contains(introSection, "Allow token introspection without audience check") {
		t.Fatal("Keycloak section points at the compatibility bypass")
	}
	introCfg, err := config.Load(writeDoorConfig(t, introRaw+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	intro := introCfg.MCPDoor
	if !intro.Enabled || intro.Mode != config.MCPDoorIntrospection || intro.ClientID != introspectionClient ||
		len(intro.Enrollments) != 1 || intro.Enrollments[0].ClientID == introspectionClient ||
		intro.IntrospectionURL != intro.Issuer+"/protocol/openid-connect/token/introspect" {
		t.Fatalf("introspection example = %+v", intro)
	}

	signer, keyPath := runtimeDoorIssuer(t)
	path := writeDoorConfig(t, strings.Replace(raw, jwksPlaceholder, strconv.Quote(keyPath), 1)+"\n")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	profile := cfg.MCPDoor
	if !profile.Enabled || profile.Mode != config.MCPDoorJWT || len(profile.Enrollments) != 1 {
		t.Fatal("the guide's JWT example must enable the door and enroll one caller")
	}
	if profile.Issuer != intro.Issuer || profile.Audience != intro.Audience {
		t.Fatalf("guide examples diverged: jwt issuer %s audience %s, introspection issuer %s audience %s", profile.Issuer, profile.Audience, intro.Issuer, intro.Audience)
	}
	resource, err := url.Parse(profile.Audience)
	if err != nil {
		t.Fatal(err)
	}

	var dials atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(doorStaticAuthHeader) != "" {
			t.Error("door bearer reached upstream")
		}
		writeDoorTools(w)
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			dials.Add(1)
		}
	}
	upstream.Start()
	t.Cleanup(upstream.Close)

	base, err := startDoorCommand(t, path, upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	caller := profile.Enrollments[0]
	for _, tc := range []struct {
		name, token, challenge string
		status                 int
		dials                  int32
	}{
		{
			"bad token", runtimeDoorToken(t, signer, profile.Issuer, "https://wrong.example/mcp", caller.Subject, caller.ClientID),
			`Bearer resource_metadata="https://mcp.vendor.example/.well-known/oauth-protected-resource/mcp", error="invalid_token"`, http.StatusUnauthorized, 0,
		},
		{"unenrolled", runtimeDoorToken(t, signer, profile.Issuer, profile.Audience, caller.Subject+"-other", caller.ClientID), "", http.StatusForbidden, 0},
		{"enrolled", runtimeDoorToken(t, signer, profile.Issuer, profile.Audience, caller.Subject, caller.ClientID), "", http.StatusOK, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, challenge := runtimeDoorToolsList(t, t.Context(), base+resource.EscapedPath(), tc.token)
			if status != tc.status || challenge != tc.challenge {
				t.Fatalf("got status %d with challenge %q, want %d with %q", status, challenge, tc.status, tc.challenge)
			}
			if got := dials.Load(); got != tc.dials {
				t.Fatalf("upstream dials = %d, want %d", got, tc.dials)
			}
		})
	}
	t.Run("static Authorization", func(t *testing.T) {
		_, err := startDoorCommand(t, path, upstream.URL, "--header", doorStaticAuthHeader+": "+"Bearer "+"static-fixture")
		if err == nil || !strings.Contains(err.Error(), "mcp_door cannot be combined with static upstream Authorization") {
			t.Fatalf("startup with a static Authorization header returned %v", err)
		}
		if got := dials.Load(); got != 1 {
			t.Fatalf("startup refusal changed upstream dials to %d", got)
		}
	})
}

func writeDoorTools(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
}

func runtimeDoorToolsList(t *testing.T, ctx context.Context, endpoint, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/list")
	if token != "" {
		req.Header.Set(doorStaticAuthHeader, "Bearer "+token)
	}
	client := &http.Client{Timeout: testwait.Deadline(10 * time.Second)}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
}

func TestMCPDoorStartupRefusals(t *testing.T) {
	raw, _ := runtimeDoorConfig(t)
	tokenFile := filepath.Join(t.TempDir(), "static")
	if err := os.WriteFile(tokenFile, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()
	for _, tc := range []struct {
		name, raw string
		flags     []string
		want      string
	}{
		{"issuer", strings.Replace(raw, "  issuer: https://issuer.example\n", "", 1), nil, "issuer"},
		{"audience", strings.Replace(raw, "  audience: https://resource.example/mcp\n", "", 1), nil, "audience"},
		{"missing keys", strings.Replace(raw, "  jwks_file:", "  unused_file:", 1), nil, "field unused_file"},
		{"unavailable keys", fmt.Sprintf("mcp_door:\n  enabled: true\n  issuer: https://issuer.example\n  audience: https://resource.example/mcp\n  mode: jwt\n  jwks_file: %q\n", filepath.Join(t.TempDir(), "missing.json")), nil, "verifier material unavailable"},
		{"anonymous fallback", raw, []string{"--listener-allow-unauthenticated"}, "cannot be combined"},
		{"static fallback", raw, []string{"--listener-auth-token-file", tokenFile}, "cannot be combined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := McpCmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetIn(strings.NewReader(""))
			args := []string{"proxy", "--listen", "0.0.0.0:0", "--upstream", upstream.URL, "--config", writeDoorConfig(t, tc.raw)}
			cmd.SetArgs(append(args, tc.flags...))
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("startup %v, want %q", err, tc.want)
			}
			if calls.Load() != 0 {
				t.Fatal("startup refusal contacted upstream")
			}
		})
	}
	path := writeDoorConfig(t, raw)
	cmd := McpCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"proxy", "--upstream", upstream.URL, "--config", path})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "requires mcp proxy --listen") {
		t.Fatalf("non-listener silently ignored door: %v", err)
	}
	if _, err := NewServer(ServerOpts{ConfigFile: path}); err == nil || !strings.Contains(err.Error(), "run does not support door mode") {
		t.Fatalf("run silently ignored door: %v", err)
	}
}

func TestMCPDoorCommandNonLoopback(t *testing.T) {
	raw, token := runtimeDoorConfig(t)
	path := writeDoorConfig(t, raw)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get(doorStaticAuthHeader) != "" {
			t.Error("door token forwarded")
		}
		writeDoorTools(w)
	}))
	defer upstream.Close()
	testport.WithRetry(t, 1, func(addrs []string) (runErr error) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cmd := McpCmd()
		cmd.SetContext(ctx)
		cmd.SetOut(io.Discard)
		var stderr syncBuffer
		cmd.SetErr(&stderr)
		cmd.SetArgs([]string{"proxy", "--listen", strings.Replace(addrs[0], "127.0.0.1", "0.0.0.0", 1), "--upstream", upstream.URL, "--config", path})
		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()
		exited := false
		defer func() {
			cancel()
			if exited {
				return
			}
			select {
			case err := <-done:
				if runErr == nil && err != nil && !errors.Is(err, context.Canceled) {
					runErr = fmt.Errorf("door command stop: %w", err)
				}
			case <-time.After(testwait.Deadline(10 * time.Second)):
				if runErr == nil {
					runErr = errors.New("door command did not stop")
				}
			}
		}()
		base := "http://" + addrs[0]
		ready := func() bool {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
			if err != nil {
				return false
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return false
			}
			_ = resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		}
		// A bind collision makes the command exit before it is ready; return that
		// error so WithRetry can try another port instead of waiting out the deadline.
		deadline := time.After(testwait.Deadline(10 * time.Second))
		for !ready() {
			select {
			case err := <-done:
				exited = true
				return fmt.Errorf("door command exited before ready: %w; stderr %s", err, stderr.String())
			case <-deadline:
				return fmt.Errorf("door command listener not ready; stderr %s", stderr.String())
			case <-time.After(20 * time.Millisecond):
			}
		}
		for _, auth := range []string{"", token} {
			status, _ := runtimeDoorToolsList(t, ctx, base+"/", auth)
			want := http.StatusOK
			if auth == "" {
				want = http.StatusUnauthorized
			}
			if status != want {
				t.Fatalf("door command: %d want %d; stderr %s", status, want, stderr.String())
			}
		}
		if calls.Load() != 1 {
			t.Fatalf("backend calls %d want 1", calls.Load())
		}
		return nil
	})
}
