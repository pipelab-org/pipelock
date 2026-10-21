// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// An enforced URL block must keep its block evidence and adaptive points on
// every URL entry point. The recorder and the transport share one URL
// verdict; if a transport recorded an enforced block as an observation, the
// refusal would add no points and explicit blocks would stop escalating.
func TestEnforcedURLBlockScoresOnEveryTransport(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()
	coreValue := "gh" + "p_" + strings.Repeat("aB3c", 9)
	for _, transport := range []string{"fetch", "forward", "connect", "websocket"} {
		for _, producer := range []string{"enforced_blocklist", "audit_core_floor"} {
			// A CONNECT authority carries no query, so it can't hold a
			// supplied-URL credential.
			if transport == "connect" && producer == "audit_core_floor" {
				continue
			}
			t.Run(transport+"/"+producer, func(t *testing.T) {
				configure := func(cfg *config.Config) {
					adaptiveWarnTransportConfig(cfg)
					if producer == "enforced_blocklist" {
						enforce := true
						cfg.Enforce = &enforce
						return
					}
					cfg.FetchProxy.Monitoring.Blocklist = nil
				}
				var proxyAddr string
				var p *Proxy
				var cleanup func()
				target := backend.URL
				if transport == "websocket" {
					var closeBackend func()
					target, closeBackend = wsEchoServer(t)
					defer closeBackend()
					target = "ws://" + target
					proxyAddr, p, cleanup = setupWSProxyDefaultWithProxy(t, configure)
				} else {
					proxyAddr, p, cleanup = setupForwardProxyWithInstance(t, configure)
				}
				defer cleanup()
				if producer == "audit_core_floor" {
					target += "/?value=" + coreValue
				}
				parsedTarget, err := url.Parse(target)
				if err != nil {
					t.Fatal(err)
				}
				rec := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyLoopback)

				var refused bool
				switch transport {
				case "websocket":
					conn, err := dialWSConnToTarget(proxyAddr, target)
					if err == nil {
						_ = conn.Close()
					}
					refused = err != nil && strings.Contains(err.Error(), "403")
				case "connect":
					conn := dialProxy(t, proxyAddr)
					defer func() { _ = conn.Close() }()
					if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", parsedTarget.Host, parsedTarget.Host); err != nil {
						t.Fatal(err)
					}
					resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
					if err != nil {
						t.Fatal(err)
					}
					_ = resp.Body.Close()
					refused = resp.StatusCode == http.StatusForbidden
				default:
					client := http.DefaultClient
					reqURL := "http://" + proxyAddr + "/fetch?url=" + url.QueryEscape(target)
					if transport == "forward" {
						parsedProxy, err := url.Parse("http://" + proxyAddr)
						if err != nil {
							t.Fatal(err)
						}
						tr := &http.Transport{Proxy: http.ProxyURL(parsedProxy)}
						defer tr.CloseIdleConnections()
						client = &http.Client{Transport: tr}
						reqURL = target
					}
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, reqURL, nil)
					if err != nil {
						t.Fatal(err)
					}
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					_ = resp.Body.Close()
					refused = resp.StatusCode == http.StatusForbidden
				}
				if !refused {
					t.Fatal("enforced URL block was delivered")
				}

				if got := rec.ThreatScore(); got <= 0 {
					t.Fatalf("enforced URL block added no adaptive points: score=%v", got)
				}
				events := rec.RecentEvents()
				if len(events) == 0 {
					t.Fatal("enforced URL block left no session evidence")
				}
				for _, event := range events {
					if event.Kind != config.ActionBlock || event.Severity != config.SeverityCritical {
						t.Fatalf("enforced URL block recorded as an observation: %+v", event)
					}
				}
			})
		}
	}
}
