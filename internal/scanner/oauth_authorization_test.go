// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const oauthTestEndpoint = "https://auth.vendor.example/oauth/authorize"

func oauthTestConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = nil
	cfg.APIAllowlist = nil
	cfg.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = []config.OAuthAuthorizationEndpoint{{Host: "auth.vendor.example", Path: "/oauth/authorize"}}
	return cfg
}

func oauthTestURL(redirect string) string {
	q := url.Values{"response_type": {"code"}, "client_id": {"native-client"}, "redirect_uri": {redirect}, "state": {entropyTestMixed}, "nonce": {entropyTestAlphabet}, "code_challenge": {rfc7636Challenge}, "code_challenge_method": {"S256"}}
	return oauthTestEndpoint + "?" + q.Encode()
}

func TestNativeOAuthAuthorization(t *testing.T) {
	base := oauthTestURL("http://127.0.0.1:49152/callback")
	tests := []struct {
		name    string
		method  string
		change  func(string) string
		allow   bool
		scanner string
	}{
		{name: "IPv4 variable port", method: http.MethodGet, allow: true},
		{name: "IPv6", method: http.MethodGet, change: func(string) string { return oauthTestURL("http://[::1]:54321/callback") }, allow: true},
		{name: "localhost", method: http.MethodGet, change: func(string) string { return oauthTestURL("http://localhost:54321/callback") }, allow: true},
		{name: "implicit port", method: http.MethodGet, change: func(string) string { return oauthTestURL("http://127.0.0.1/callback") }, allow: true},
		{name: "no method", scanner: ScannerEntropy},
		{name: "POST", method: http.MethodPost, scanner: ScannerEntropy},
		{name: "CONNECT", method: http.MethodConnect, scanner: ScannerEntropy},
		{name: "WebSocket", method: "WS", scanner: ScannerEntropy},
		{name: "other endpoint", method: http.MethodGet, change: func(s string) string { return strings.Replace(s, "/oauth/authorize?", "/relay?", 1) }, scanner: ScannerEntropy},
		{name: "other host", method: http.MethodGet, change: func(s string) string { return strings.Replace(s, "auth.vendor.example", "api.vendor.example", 1) }, scanner: ScannerEntropy},
		{name: "cleartext", method: http.MethodGet, change: func(s string) string { return strings.Replace(s, "https:", "http:", 1) }, scanner: ScannerEntropy},
		{name: "other endpoint port", method: http.MethodGet, change: func(s string) string { return strings.Replace(s, "auth.vendor.example", "auth.vendor.example:8443", 1) }, scanner: ScannerEntropy},
		{name: "duplicate state", method: http.MethodGet, change: func(s string) string { return s + "&state=other" }, scanner: ScannerEntropy},
		{name: "encoded duplicate", method: http.MethodGet, change: func(s string) string { return s + "&%73tate=other" }, scanner: ScannerEntropy},
		{name: "duplicate unrelated", method: http.MethodGet, change: func(s string) string { return s + "&scope=one&scope=two" }, scanner: ScannerEntropy},
		{name: "duplicate redirect", method: http.MethodGet, change: func(s string) string { return s + "&redirect_uri=http://127.0.0.1/cb" }, scanner: ScannerEntropy},
		{name: "response type spoof", method: http.MethodGet, change: func(s string) string { return strings.Replace(s, "response_type=code", "response_type=codeword", 1) }, scanner: ScannerEntropy},
		{name: "hybrid response", method: http.MethodGet, change: func(s string) string {
			return strings.Replace(s, "response_type=code", "response_type=code+id_token", 1)
		}, scanner: ScannerEntropy},
		{name: "duplicate response", method: http.MethodGet, change: func(s string) string { return s + "&response_type=code" }, scanner: ScannerEntropy},
		{name: "invalid PKCE", method: http.MethodGet, change: func(s string) string { return strings.Replace(s, "method=S256", "method=plain", 1) }, scanner: ScannerEntropy},
		{name: "malformed escape", method: http.MethodGet, change: func(s string) string { return s + "&extra=%ZZ" }, scanner: ScannerEntropy},
		{name: "semicolon", method: http.MethodGet, change: func(s string) string { return s + ";extra=value" }, scanner: ScannerEntropy},
		{name: "empty pair", method: http.MethodGet, change: func(s string) string { return s + "&" }, scanner: ScannerEntropy},
		{name: "request object", method: http.MethodGet, change: func(s string) string { return s + "&request=object" }, scanner: ScannerEntropy},
		{name: "PAR", method: http.MethodGet, change: func(s string) string { return s + "&request_uri=urn:example:request" }, scanner: ScannerEntropy},
		{name: "missing client", method: http.MethodGet, change: func(s string) string { return strings.Replace(s, "client_id=native-client", "client_id=", 1) }, scanner: ScannerEntropy},
		{name: "adjacent data", method: http.MethodGet, change: func(s string) string { return s + "&data=" + entropyTestMixed }, scanner: ScannerEntropy},
		{name: "DLP state", method: http.MethodGet, change: func(s string) string { return strings.Replace(s, entropyTestMixed, "ghp_"+strings.Repeat("A", 36), 1) }, scanner: ScannerCoreDLP},
		{name: "DLP callback path", method: http.MethodGet, change: func(string) string { return oauthTestURL("http://127.0.0.1:49152/ghp_" + strings.Repeat("A", 36)) }, scanner: ScannerCoreDLP},
		{name: "callback path entropy", method: http.MethodGet, change: func(string) string { return oauthTestURL("http://127.0.0.1:49152/" + entropyTestMixed) }, scanner: ScannerEntropy},
		{name: "callback query entropy", method: http.MethodGet, change: func(string) string { return oauthTestURL("http://127.0.0.1:49152/cb?data=" + entropyTestMixed) }, scanner: ScannerEntropy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := base
			if tt.change != nil {
				raw = tt.change(raw)
			}
			s := MustNew(oauthTestConfig())
			defer s.Close()
			result := s.Scan(WithOAuthAuthorizationMethod(t.Context(), tt.method), raw)
			if result.Allowed != tt.allow || !tt.allow && result.Scanner != tt.scanner {
				t.Fatalf("got %+v, want allowed=%v scanner=%s", result, tt.allow, tt.scanner)
			}
		})
	}
}

func TestNativeOAuthLoopbackBoundary(t *testing.T) {
	for _, redirect := range []string{
		"http://0x7f.1/cb", "http://127.1/cb", "http://[::ffff:127.0.0.1]/cb", "http://127.0.0.1./cb", "http://localhost./cb", "http://localhost.vendor.example/cb",
		"http://127.0.0.1@192.168.1.1/cb", "http://user@127.0.0.1/cb", "https://127.0.0.1/cb", "http://192.168.1.1/cb", "http://169.254.169.254/latest", "http://127.0.0.1:/cb", "http://127.0.0.1:0/cb", "http://127.0.0.1:65536/cb", "http://127%2e0.0.1/cb", "http://127.0.0.1/cb#fragment", "http://127.0.0.1\\@api.vendor.example/cb",
	} {
		t.Run(redirect, func(t *testing.T) {
			s := MustNew(oauthTestConfig())
			defer s.Close()
			result := s.Scan(WithOAuthAuthorizationMethod(t.Context(), http.MethodGet), oauthTestURL(redirect))
			if result.Allowed {
				t.Fatal("nonliteral or malformed loopback admitted")
			}
		})
	}
}

func TestNativeOAuthGrantLifecycleAndScope(t *testing.T) {
	raw := oauthTestURL("http://127.0.0.1:49152/callback")
	ctx := WithOAuthAuthorizationMethod(t.Context(), http.MethodGet)
	for _, name := range []string{"absent", "expired", "active", "removed"} {
		t.Run(name, func(t *testing.T) {
			cfg := oauthTestConfig()
			switch name {
			case "absent", "removed":
				cfg.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = nil
			case "expired":
				cfg.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0].Expires = time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
			}
			s := MustNew(cfg)
			defer s.Close()
			got := s.Scan(ctx, raw)
			if got.Allowed != (name == "active") {
				t.Fatalf("%s: %+v", name, got)
			}
		})
	}
	s := MustNew(oauthTestConfig())
	defer s.Close()
	if got := s.Scan(ctx, "http://127.0.0.1:49152/callback?code=short"); got.Allowed || got.Scanner != ScannerCoreSSRF {
		t.Fatalf("direct callback: %+v", got)
	}
	// Without random state, only the descriptor gate can decide this request.
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	q.Set("state", "csrf")
	q.Del("nonce")
	parsed.RawQuery = q.Encode()
	if got := s.Scan(ctx, parsed.String()); !got.Allowed {
		t.Fatalf("PKCE callback descriptor: %+v", got)
	}
	q.Del("code_challenge")
	q.Del("code_challenge_method")
	parsed.RawQuery = q.Encode()
	if got := s.Scan(ctx, parsed.String()); !got.Allowed {
		t.Fatalf("state-only: %+v", got)
	}
	q.Del("state")
	parsed.RawQuery = q.Encode()
	if got := s.Scan(ctx, parsed.String()); got.Allowed || got.Scanner != ScannerCoreSSRF {
		t.Fatalf("missing state and PKCE: %+v", got)
	}
	// The grant never authorizes another private destination in the same query,
	// including a target nested within the callback descriptor itself.
	for _, extra := range []string{"&target=http://192.168.1.1/", "&redirect=http://169.254.169.254/"} {
		if got := s.Scan(ctx, raw+extra); got.Allowed {
			t.Fatalf("adjacent destination: %+v", got)
		}
	}
	if got := s.Scan(ctx, oauthTestURL("http://127.0.0.1/cb?target=http://192.168.1.1/")); got.Allowed {
		t.Fatal("callback nested destination admitted")
	}
	cfg := oauthTestConfig()
	cfg.FetchProxy.Monitoring.MaxURLLength = len(raw) - 1
	limited := MustNew(cfg)
	defer limited.Close()
	if got := limited.Scan(ctx, raw); got.Allowed || got.Scanner != ScannerLength {
		t.Fatalf("URL limit: %+v", got)
	}
	if got := s.Scan(context.Background(), raw); got.Allowed {
		t.Fatal("URL-only scanner gained grant")
	}
}

func TestNativeOAuthRecognitionBoundaries(t *testing.T) {
	s := MustNew(oauthTestConfig())
	defer s.Close()
	ctx := WithOAuthAuthorizationMethod(t.Context(), http.MethodGet)
	parsed, err := url.Parse(oauthTestURL("http://127.0.0.1/callback"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*url.URL)
		allow  bool
	}{
		{name: "valid", allow: true, change: func(*url.URL) {}},
		{name: "endpoint userinfo", change: func(u *url.URL) { u.User = url.User("caller") }},
		{name: "endpoint fragment", change: func(u *url.URL) { u.Fragment = "data" }},
		{name: "endpoint invalid host", change: func(u *url.URL) { u.Host = "bad_host" }},
		{name: "empty key", change: func(u *url.URL) { u.RawQuery += "&=value" }},
		{name: "bare component", change: func(u *url.URL) { u.RawQuery += "&bare" }},
		{name: "missing redirect", change: func(u *url.URL) { q := u.Query(); q.Del("redirect_uri"); u.RawQuery = q.Encode() }},
		{name: "malformed redirect", change: func(u *url.URL) { q := u.Query(); q.Set("redirect_uri", "http://[invalid/cb"); u.RawQuery = q.Encode() }},
		{name: "relative redirect", change: func(u *url.URL) { q := u.Query(); q.Set("redirect_uri", "/callback"); u.RawQuery = q.Encode() }},
		{name: "HTTPS invalid port", change: func(u *url.URL) {
			q := u.Query()
			q.Set("redirect_uri", "https://api.vendor.example:65536/cb")
			u.RawQuery = q.Encode()
		}},
		{name: "HTTPS missing host", change: func(u *url.URL) { q := u.Query(); q.Set("redirect_uri", "https:///callback"); u.RawQuery = q.Encode() }},

		{name: "query parse error", change: func(u *url.URL) { u.RawQuery += "&extra=%ZZ" }},
		{name: "duplicate parameter", change: func(u *url.URL) { u.RawQuery += "&scope=one&scope=two" }},
		{name: "empty component", change: func(u *url.URL) { u.RawQuery += "&" }},
		{name: "missing client identifier", change: func(u *url.URL) { q := u.Query(); q.Del("client_id"); u.RawQuery = q.Encode() }},
		{name: "wrong response type", change: func(u *url.URL) { q := u.Query(); q.Set("response_type", "code id_token"); u.RawQuery = q.Encode() }},
		{name: "PAR override", change: func(u *url.URL) { u.RawQuery += "&request_uri=urn:example:request" }},
		{name: "bad S256 challenge", change: func(u *url.URL) { q := u.Query(); q.Set("code_challenge", "short"); u.RawQuery = q.Encode() }},
		{name: "plain challenge", change: func(u *url.URL) { q := u.Query(); q.Set("code_challenge_method", "plain"); u.RawQuery = q.Encode() }},
		{name: "no state or PKCE", change: func(u *url.URL) {
			q := u.Query()
			q.Del("state")
			q.Del("code_challenge")
			q.Del("code_challenge_method")
			u.RawQuery = q.Encode()
		}},
		{name: "userinfo callback", change: func(u *url.URL) {
			q := u.Query()
			q.Set("redirect_uri", "http://user@127.0.0.1/cb")
			u.RawQuery = q.Encode()
		}},
		{name: "fragment callback", change: func(u *url.URL) {
			q := u.Query()
			q.Set("redirect_uri", "http://127.0.0.1/cb#fragment")
			u.RawQuery = q.Encode()
		}},
		{name: "non-loopback HTTP", change: func(u *url.URL) {
			q := u.Query()
			q.Set("redirect_uri", "http://api.vendor.example/cb")
			u.RawQuery = q.Encode()
		}},
		// The server echoes state to a remote callback any client can register.
		{name: "claimed HTTPS", change: func(u *url.URL) {
			q := u.Query()
			q.Set("redirect_uri", "https://app.vendor.example/callback")
			u.RawQuery = q.Encode()
		}},
		{name: "private-use scheme", allow: true, change: func(u *url.URL) {
			q := u.Query()
			q.Set("redirect_uri", "com.vendor.app:/callback")
			u.RawQuery = q.Encode()
		}},
		// RFC 8252 7.1: a private-use scheme is a reverse-order domain name.
		{name: "non-domain scheme", change: func(u *url.URL) {
			q := u.Query()
			q.Set("redirect_uri", "myapp:/callback")
			u.RawQuery = q.Encode()
		}},
		{name: "network scheme", change: func(u *url.URL) {
			q := u.Query()
			q.Set("redirect_uri", "wss://app.vendor.example/callback")
			u.RawQuery = q.Encode()
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			u := *parsed
			tt.change(&u)
			if got := s.nativeOAuthAuthorization(ctx, &u, time.Now()); (got != nil) != tt.allow {
				t.Fatalf("recognition=%v want=%v", got != nil, tt.allow)
			}
		})
	}
	if got := s.nativeOAuthAuthorization(ctx, nil, time.Now()); got != nil {
		t.Fatal("nil URL recognized")
	}
	if got := s.nativeOAuthAuthorization(ctx, parsed, time.Now().AddDate(0, 0, 2)); got == nil {
		t.Fatal("nonexpiring grant inactive")
	}
	cfg := oauthTestConfig()
	cfg.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0].Host = "*.vendor.example"
	if _, err := New(cfg); err == nil {
		t.Fatal("scanner accepted unvalidated wildcard grant")
	}
	// A private-use callback stays on this machine; a remote HTTPS callback would
	// receive the server's echo of state, so it keeps the ordinary entropy gate.
	if got := s.Scan(ctx, oauthTestURL("com.vendor.app:/cb")); !got.Allowed {
		t.Fatalf("private-use redirect: %+v", got)
	}
	if got := s.Scan(ctx, oauthTestURL("https://app.vendor.example/cb")); got.Allowed || got.Scanner != ScannerEntropy {
		t.Fatalf("remote HTTPS redirect: %+v", got)
	}
}

func TestNativeOAuthLiteralLoopback(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1/cb", "http://[::1]:65535/cb", "http://localhost:1/cb"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !literalOAuthLoopback(u) {
			t.Fatal("valid callback refused")
		}
	}
	for _, raw := range []string{"https://127.0.0.1/cb", "http://user@127.0.0.1/cb", "http://127.0.0.1/cb#fragment", "http://127.1/cb", "http://127.0.0.1:/cb", "http://127.0.0.1:0/cb", "http://127.0.0.1:65536/cb"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if literalOAuthLoopback(u) {
			t.Fatalf("invalid literal callback accepted: %s", raw)
		}
	}
	if literalOAuthLoopback(&url.URL{Scheme: "http", Host: "127.0.0.1", Opaque: "opaque"}) {
		t.Fatal("opaque callback")
	}
	if literalOAuthLoopback(&url.URL{Scheme: "http", Host: "127.0.0.1%25"}) {
		t.Fatal("encoded host")
	}
}

func TestNativeOAuthLivePolicy(t *testing.T) {
	cfg := oauthTestConfig()
	s := MustNew(cfg)
	defer s.Close()
	method := WithOAuthAuthorizationMethod(t.Context(), http.MethodGet)
	target := oauthTestURL("http://127.0.0.1/callback")
	for _, name := range []string{"unchanged", "removed", "invalid", "nil"} {
		t.Run(name, func(t *testing.T) {
			live := cfg.Clone()
			switch name {
			case "removed":
				live.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = nil
			case "invalid":
				live.FetchProxy.Monitoring.OAuthAuthorizationEndpoints[0].Host = "*.vendor.example"
			case "nil":
				live = nil
			}
			got := s.Scan(WithOAuthAuthorizationPolicy(method, live), target)
			if got.Allowed != (name == "unchanged") {
				t.Fatalf("live %s: %+v", name, got)
			}
		})
	}
}

func TestNativeOAuthLivePolicyCannotAddToOldScanner(t *testing.T) {
	live := oauthTestConfig()
	old := live.Clone()
	old.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = nil
	s := MustNew(old)
	defer s.Close()
	ctx := WithOAuthAuthorizationPolicy(WithOAuthAuthorizationMethod(t.Context(), http.MethodGet), live)
	if got := s.Scan(ctx, oauthTestURL("http://127.0.0.1/callback")); got.Allowed {
		t.Fatal("live policy expanded old scanner authority")
	}
}

// An operator who hits either native OAuth block without a grant must be able
// to find the grant from the block's own hint, not only the broader switches.
func TestNativeOAuthBlockHintsNameGrant(t *testing.T) {
	cfg := oauthTestConfig()
	cfg.FetchProxy.Monitoring.OAuthAuthorizationEndpoints = nil
	s := MustNew(cfg)
	defer s.Close()
	ctx := WithOAuthAuthorizationMethod(t.Context(), http.MethodGet)
	parsed, err := url.Parse(oauthTestURL("http://127.0.0.1:49152/callback"))
	if err != nil {
		t.Fatal(err)
	}
	entropy := s.Scan(ctx, parsed.String())
	q := parsed.Query()
	q.Set("state", "csrf")
	q.Del("nonce")
	parsed.RawQuery = q.Encode()
	callback := s.Scan(ctx, parsed.String())
	for name, result := range map[string]Result{"state entropy": entropy, "loopback callback": callback} {
		if result.Allowed {
			t.Fatalf("%s: allowed without a grant", name)
		}
		if hint := OperatorHintForResult(result.Scanner, result.Reason); !strings.Contains(hint, "`fetch_proxy.monitoring.oauth_authorization_endpoints`") {
			t.Errorf("%s (%s: %s): hint %q does not name the grant", name, result.Scanner, result.Reason, hint)
		}
	}
	// The grant relieves only values, so a key block must not offer it.
	if hint := OperatorHintForResult(ScannerEntropy, `high entropy query key "opaque" (4.50 > 4.00 threshold)`); strings.Contains(hint, "oauth_authorization_endpoints") {
		t.Errorf("key hint offers an inert grant: %q", hint)
	}
}
