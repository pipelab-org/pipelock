// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListenerOAuthDiscovery(t *testing.T) {
	opts := MCPProxyOpts{OAuthResourceURL: "http://127.0.0.1:18891/mcp", OAuthAuthorizationServer: "https://mcp.slack.com"}
	mux := http.NewServeMux()
	challenge, err := registerListenerOAuthMetadata(mux, opts)
	if err != nil || !strings.Contains(challenge, "http://127.0.0.1:18891/.well-known/oauth-protected-resource") {
		t.Fatalf("challenge=%q err=%v", challenge, err)
	}
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		req := httptest.NewRequest("GET", "http://127.0.0.1:18891"+path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var data map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 200 || data["resource"] != opts.OAuthResourceURL {
			t.Fatal(rec.Code, data)
		}
		if data["authorization_servers"].([]any)[0] != opts.OAuthAuthorizationServer {
			t.Fatal(data)
		}
		req.Host = "attacker.example"
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatal("untrusted host accepted")
		}
	}
	for _, bad := range []MCPProxyOpts{
		{OAuthResourceURL: opts.OAuthResourceURL},
		{OAuthAuthorizationServer: opts.OAuthAuthorizationServer},
		{OAuthResourceURL: "http://public.example/mcp", OAuthAuthorizationServer: opts.OAuthAuthorizationServer},
		{OAuthResourceURL: opts.OAuthResourceURL, OAuthAuthorizationServer: "http://issuer.example"},
		{OAuthResourceURL: opts.OAuthResourceURL, OAuthAuthorizationServer: "https://secret@issuer.example"},
	} {
		if _, err := registerListenerOAuthMetadata(http.NewServeMux(), bad); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}
func TestListenerOAuth401Challenge(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://attacker.example/steal"`)
		w.WriteHeader(401)
		_, _ = w.Write([]byte("UNTRUSTED BODY MUST NOT PASS"))
	}))
	defer up.Close()
	for _, enabled := range []bool{false, true} {
		opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), ListenerBearerToken: "listener-secret"}
		if enabled {
			opts.OAuthResourceURL = "http://127.0.0.1:18891/mcp"
			opts.OAuthAuthorizationServer = "https://mcp.slack.com"
		}
		base, _ := startListenerProxyWithOpts(t, up.URL, opts)
		for _, method := range []string{"GET", "POST"} {
			req, _ := http.NewRequestWithContext(context.Background(), method, base+"/mcp", strings.NewReader(jsonToolsList))
			if method == "GET" {
				req.Body = nil
				req.ContentLength = 0
				req.Header.Set("Accept", "text/event-stream")
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Proxy-Authorization", "Bearer listener-secret")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			// Without the flags the listener keeps its own 4xx relay, which
			// passes a scanned upstream 401 through. With them, the operator-
			// pinned challenge replaces the upstream reply entirely.
			if resp.StatusCode != 401 {
				t.Fatalf("method=%s enabled=%v got=%d want=401 body=%s", method, enabled, resp.StatusCode, body)
			}
			if enabled && (strings.Contains(string(body), "UNTRUSTED") || strings.Contains(resp.Header.Get("WWW-Authenticate"), "attacker")) {
				t.Fatal("upstream content escaped")
			}
			if enabled && !strings.Contains(resp.Header.Get("WWW-Authenticate"), "127.0.0.1:18891") {
				t.Fatal("missing trusted challenge")
			}
		}
		req, _ := http.NewRequest("POST", base+"/mcp", strings.NewReader(jsonToolsList))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 407 {
			t.Fatal("listener authentication bypassed", resp.StatusCode)
		}
	}
}

func TestListenerOAuthDeleteChallenge(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("untrusted upstream body"))
	}))
	defer up.Close()
	base, _ := startListenerProxyWithOpts(t, up.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t), OAuthResourceURL: "http://127.0.0.1:18891/mcp", OAuthAuthorizationServer: "https://mcp.slack.com"})
	req, err := http.NewRequest(http.MethodDelete, base+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") == "" || len(body) != 0 {
		t.Fatalf("status=%d challenge=%q body=%q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"), body)
	}
}

func TestListenerOAuthDiscoveryBrowser(t *testing.T) {
	opts := MCPProxyOpts{OAuthResourceURL: "http://127.0.0.1:18891/mcp", OAuthAuthorizationServer: "https://mcp.slack.com", ListenerAllowedOrigins: []string{"https://client.example"}}
	mux := http.NewServeMux()
	if _, err := registerListenerOAuthMetadata(mux, opts); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "http://127.0.0.1:18891/.well-known/oauth-protected-resource", nil)
			req.Header.Set("Origin", "https://client.example")
			if method == "OPTIONS" {
				req.Header.Set("Access-Control-Request-Method", "GET")
				req.Header.Set("Access-Control-Request-Headers", "Authorization")
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			want := 200
			if method == "OPTIONS" {
				want = 204
			}
			if rec.Code != want || rec.Header().Get("Access-Control-Allow-Origin") != "https://client.example" {
				t.Fatalf("status=%d headers=%v", rec.Code, rec.Header())
			}
			if method != "GET" && rec.Body.Len() != 0 {
				t.Fatal("unexpected response body")
			}
		})
	}
	for _, tc := range []struct {
		origin, method, requested string
		want                      int
	}{
		{"https://attacker.example", "GET", "", 403},
		{"https://client.example", "OPTIONS", "POST", 403},
		{"https://client.example", "POST", "", 405},
	} {
		req := httptest.NewRequest(tc.method, "http://127.0.0.1:18891/.well-known/oauth-protected-resource", nil)
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Access-Control-Request-Method", tc.requested)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("case=%+v status=%d", tc, rec.Code)
		}
		if rec.Code == 405 && rec.Header().Get("Allow") == "" {
			t.Fatal("missing Allow header")
		}
	}
}

func TestListenerOAuthBrowserChallengeExposed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }))
	defer up.Close()
	base, _ := startListenerProxyWithOpts(t, up.URL, MCPProxyOpts{Scanner: testScannerForHTTP(t), OAuthResourceURL: "http://127.0.0.1:18891/mcp", OAuthAuthorizationServer: "https://mcp.slack.com", ListenerAllowedOrigins: []string{"https://client.example"}})
	req, err := http.NewRequest("POST", base+"/mcp", strings.NewReader(jsonToolsList))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://client.example")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("Access-Control-Expose-Headers"), "WWW-Authenticate") {
		t.Fatalf("status=%d headers=%v", resp.StatusCode, resp.Header)
	}
}
