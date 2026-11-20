// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Discovery is public, static, and operator-pinned. It never forwards client
// credentials, fetches URLs supplied by an upstream, or exposes upstream bodies.
// Token exchange and storage remain the MCP client's responsibility.
func registerListenerOAuthMetadata(mux *http.ServeMux, opts MCPProxyOpts) (string, error) {
	if opts.OAuthResourceURL == "" && opts.OAuthAuthorizationServer == "" {
		return "", nil
	}
	resource, err := url.Parse(opts.OAuthResourceURL)
	if err != nil || resource.Host == "" || resource.User != nil || resource.RawQuery != "" || resource.Fragment != "" {
		return "", fmt.Errorf("invalid OAuth resource URL")
	}
	loopback := resource.Hostname() == "localhost"
	if ip := net.ParseIP(resource.Hostname()); ip != nil {
		loopback = ip.IsLoopback()
	}
	if resource.Scheme != "https" && !(resource.Scheme == "http" && loopback) {
		return "", fmt.Errorf("OAuth resource requires HTTPS or loopback HTTP")
	}
	issuer, err := url.Parse(opts.OAuthAuthorizationServer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return "", fmt.Errorf("OAuth authorization server requires a trusted HTTPS issuer URL")
	}
	metadataURL := resource.Scheme + "://" + resource.Host + "/.well-known/oauth-protected-resource"
	body, err := json.Marshal(map[string]any{
		"resource":                 opts.OAuthResourceURL,
		"authorization_servers":    []string{opts.OAuthAuthorizationServer},
		"bearer_methods_supported": []string{"header"},
	})
	if err != nil {
		return "", err
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Host != resource.Host {
			http.Error(w, "host not allowed", http.StatusForbidden)
			return
		}
		if !listenerOriginAllowed(r.Header.Values("Origin"), opts.ListenerAllowedOrigins) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Vary", "Origin")
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", listenerCORSAllowedHeaders)
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")
			if r.Method == http.MethodOptions {
				method := r.Header.Get("Access-Control-Request-Method")
				if (method != http.MethodGet && method != http.MethodHead) || !listenerCORSRequestHeadersAllowed(r) {
					http.Error(w, "CORS preflight not allowed", http.StatusForbidden)
					return
				}
				allowMCPParamCORSHeaders(w.Header(), r.Header.Get("Access-Control-Request-Headers"))
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	}
	mux.HandleFunc("/.well-known/oauth-protected-resource", handler)
	if path := strings.TrimRight(resource.EscapedPath(), "/"); path != "" {
		mux.HandleFunc("/.well-known/oauth-protected-resource"+path, handler)
	}
	return fmt.Sprintf("Bearer resource_metadata=%q", metadataURL), nil
}

// Share the same sanitized challenge path across POST, GET and DELETE. Never
// forward an upstream URL, error description or body into OAuth discovery.
func writeListenerOAuthChallenge(w http.ResponseWriter, status int, challenge string) bool {
	if status != http.StatusUnauthorized || challenge == "" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("WWW-Authenticate", challenge)
	w.WriteHeader(http.StatusUnauthorized)
	return true
}
