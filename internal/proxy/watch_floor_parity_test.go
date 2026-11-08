// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/authority"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Audit mode's existing refusal contract supplies the expected watch floor.
// Each row proves the audit refusal and verifies zero upstream dispatch in
// both modes, so a changed fixture cannot silently turn this into allow parity.
func TestWatchAuditFloorHTTPParity(t *testing.T) {
	for _, tc := range []struct {
		name, body, contentType, encoding, query string
		trailer, broken                          bool
	}{
		{name: "core body", body: auditFloorValue("core")},
		{name: "encoded body", body: auditFloorValue("core"), encoding: "gzip"},
		{name: "body overflow", body: strings.Repeat(" ", 1024) + auditFloorValue("core")},
		{name: "read failure", broken: true, body: "prefix"},
		{name: "trailers", body: "hello", trailer: true},
		{name: "JSON depth", body: strings.Repeat("[", 65) + "1" + strings.Repeat("]", 65), contentType: "application/json"},
		{name: "JSON number", body: "[1e10001]", contentType: "application/json"},
		{name: "text decode bound", body: deepEntityChain()},
		{name: "URL decode bound", query: "q=" + percentNested("hello", 501)},
		{name: "query subsequence bound", query: watchQueryLimitFixture()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, surface := range []string{TransportForward, TransportReverse, "intercept"} {
				for _, watch := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/watch=%t", surface, watch), func(t *testing.T) {
						var hits atomic.Int32
						upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
							hits.Add(1)
							w.WriteHeader(http.StatusOK)
						}))
						defer upstream.Close()
						_, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
							auditFloorConfig(false, "")(cfg)
							cfg.WatchOnly = watch
							cfg.RequestBodyScanning.MaxBodyBytes = 1024
						})
						defer cleanup()
						req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL+"/upload?"+tc.query, strings.NewReader(tc.body))
						req.Header.Set("Content-Type", tc.contentType)
						req.Header.Set("Content-Encoding", tc.encoding)
						if tc.trailer {
							req.Trailer = http.Header{"X-Trailer": {"hello"}}
						}
						if tc.broken {
							req.Body = watchBrokenResponse{}
						}
						out := httptest.NewRecorder()
						switch surface {
						case TransportReverse:
							u, err := url.Parse(upstream.URL)
							if err != nil {
								t.Fatal(err)
							}
							rp := NewReverseProxy(u, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
							rp.SetOwnerProxy(p)
							rp.ServeHTTP(out, req)
						case "intercept":
							req.URL.Scheme, req.URL.Host, req.Host = "https", "api.vendor.example", "api.vendor.example"
							handler := newInterceptHandler(&InterceptContext{TargetHost: req.Host, TargetPort: "443", Config: p.cfgPtr.Load(), Scanner: p.scannerPtr.Load(), Logger: p.logger, Metrics: p.metrics, Proxy: p},
								roundTripperFunc(func(r *http.Request) (*http.Response, error) {
									hits.Add(1)
									return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
								}))
							handler.ServeHTTP(out, req)
						default:
							p.handleForwardHTTP(out, req)
						}
						wantStatus, wantHits := http.StatusForbidden, int32(0)
						if surface == TransportReverse && !watch {
							if tc.name == "body overflow" {
								wantStatus = http.StatusRequestEntityTooLarge
							}
							// Reverse's configured upstream skips the URL pipeline.
							if tc.query != "" {
								wantStatus, wantHits = http.StatusOK, 1
							}
						}
						if out.Code != wantStatus || hits.Load() != wantHits {
							t.Fatalf("audit floor lost: status=%d upstream=%d response=%s", out.Code, hits.Load(), out.Body)
						}
					})
				}
			}
		})
	}
}

func TestWatchAuditFloorUnavailableScanner(t *testing.T) {
	cfg := config.Defaults()
	cfg.WatchOnly = true
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, watchReloadTarget, nil)
	if !watchRequestDecision(req, watchHTTPOptions{Config: cfg, Logger: audit.NewNop(), Metrics: metrics.New(), Transport: TransportForward}) {
		t.Fatal("unavailable outbound scanner admitted request")
	}
}

func TestWatchAuditFloorDial(t *testing.T) {
	cfg := testScannerConfig()
	cfg.WatchOnly = true
	cfg.Internal = []string{"127.0.0.0/8"}
	cfg.SSRF.IPAllowlist = nil
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	upstream := listenEcho(t)
	defer func() { _ = upstream.Close() }()
	for _, snapshot := range []bool{false, true} {
		ctx := t.Context()
		if snapshot {
			ctx = context.WithValue(ctx, watchModeContextKey{}, watchHTTPOptions{Config: cfg, Scanner: sc, Logger: p.logger, Metrics: p.metrics, Transport: TransportForward})
		}
		conn, err := p.ssrfSafeDialContext(ctx, "tcp", upstream.Addr().String())
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			t.Fatalf("host protection bypassed, admitted snapshot=%t", snapshot)
		}
	}
}

func TestWatchFetchRedirectLimit(t *testing.T) {
	var hits atomic.Int32
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n < 7 {
			http.Redirect(w, r, fmt.Sprintf("/hop/%d", n), http.StatusFound)
		} else {
			_, _ = io.WriteString(w, "too far")
		}
	}))
	defer upstream.Close()
	_, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) { cfg.WatchOnly = true })
	defer cleanup()
	out := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL), nil)
	p.handleFetch(out, req)
	// The cap still stops the chain; like audit mode, an exhausted chain is an
	// upstream failure rather than an enforced block.
	if out.Code != http.StatusBadGateway || out.Header().Get("X-Pipelock-Block-Reason") != "" || hits.Load() != maxFetchRedirects {
		t.Fatalf("redirect cap lost: status=%d reason=%q hops=%d", out.Code, out.Header().Get("X-Pipelock-Block-Reason"), hits.Load())
	}
	audit := httptest.NewRecorder()
	_, auditProxy, auditCleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) { cfg.Enforce = ptrBool(false) })
	defer auditCleanup()
	hits.Store(0)
	auditProxy.handleFetch(audit, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL), nil))
	if audit.Code != out.Code {
		t.Fatalf("watch-only redirect cap status %d differs from audit %d", out.Code, audit.Code)
	}
}

func TestWatchConnectAuthorityParity(t *testing.T) {
	for _, payload := range [][]byte{buildClientHello("other.vendor.example"), []byte("not TLS")} {
		upstream := listenEcho(t)
		defer func() { _ = upstream.Close() }()
		proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
			cfg.WatchOnly = true
			cfg.ForwardProxy.SNIRequireTLS = ptrBool(true)
		})
		defer cleanup()
		conn := dialProxy(t, proxyAddr)
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		target := upstream.Addr().String()
		_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT status=%d", resp.StatusCode)
		}
		_, _ = conn.Write(payload)
		buf := make([]byte, len(payload))
		n, err := io.ReadFull(reader, buf)
		if err == nil || n != 0 {
			t.Fatalf("authority failure relayed %d bytes", n)
		}
	}
}

func watchQueryLimitFixture() string {
	// Same boundary fixture as scanner.TestQueryValuesPastPairSearchRefused.
	q := make([]string, 112)
	for i := range q {
		q[i] = fmt.Sprintf("a%d=%d", i, i%10)
	}
	return strings.Join(q, "&")
}

func TestWatchRequestPolicyAdmittedConfig(t *testing.T) {
	for _, watch := range []bool{false, true} {
		cfg := reqPolicyConfig(graphqlBlockRule())
		cfg.WatchOnly = !watch
		cfg.RequestBodyScanning.MaxBodyBytes = 8
		p := newTestProxyWithConfig(t, cfg)
		admitted := cfg.Clone()
		admitted.WatchOnly = watch
		body := deleteRecordGraphQLBody()
		ctx := context.WithValue(t.Context(), ctxKeyAgentConfig, admitted)
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "http://"+rpTestHost+"/graphql", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		in := requestPolicyInput{
			Host: rpTestHost, Method: http.MethodPost, Path: "/graphql",
			ContentType: "application/json", Headers: req.Header, Transport: TransportForward,
		}
		result := p.prepareRequestPolicyBody(req, &in)
		if result.Block == watch {
			t.Fatalf("live config replaced admitted watch=%t: %+v", watch, result)
		}
		if watch {
			got, err := io.ReadAll(req.Body)
			if err != nil || string(got) != body {
				t.Fatalf("body replay changed: %q %v", got, err)
			}
		}
	}
}

func TestWatchFetchRedirectAuthority(t *testing.T) {
	var deniedHits, verified atomic.Int32
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/denied", http.StatusFound)
			return
		}
		deniedHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	_, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) { cfg.WatchOnly = true })
	defer cleanup()
	p.authorityVerifier = proxyAuthorityVerifierFunc(func(_ context.Context, request authority.Request) authority.Result {
		verified.Add(1)
		decision := authority.DecisionDeny
		if strings.HasSuffix(request.Destination, "/start") {
			decision = authority.DecisionAllow
		}
		return authority.Result{Decision: decision, Reason: authority.ReasonActionMismatch}
	})
	out := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL+"/start"), nil)
	req.Header.Set(authority.HTTPHeader, "grant")
	p.handleFetch(out, req)
	if out.Code < 400 || deniedHits.Load() != 0 || verified.Load() != 2 {
		t.Fatalf("redirect authority lost: status=%d denied=%d verified=%d", out.Code, deniedHits.Load(), verified.Load())
	}
}

func TestWatchHTTPEmittedReceiptMarker(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprintf("blocked=%t", blocked), func(t *testing.T) {
			_, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) { cfg.WatchOnly = true })
			defer cleanup()
			helper := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(helper.emitter)
			var hits atomic.Int32
			upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			body := "hello"
			if blocked {
				body = auditFloorValue("core")
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL, strings.NewReader(body))
			out := httptest.NewRecorder()
			p.handleForwardHTTP(out, req)
			wantVerdict, marker := config.ActionAllow, "watch_only: observation"
			if blocked {
				wantVerdict, marker = config.ActionBlock, "watch_only: enforced in watch-only"
			}
			if (out.Code == http.StatusForbidden) != blocked || (hits.Load() == 0) != blocked {
				t.Fatalf("wrong dispatch: %d %d", out.Code, hits.Load())
			}
			receipts := helper.findReceipts(t)
			found := false
			for _, r := range receipts {
				if r.ActionRecord.Verdict == wantVerdict && strings.Contains(r.ActionRecord.Pattern, marker) {
					if err := receipt.VerifyWithKey(r, helper.pubHex); err != nil {
						t.Fatal(err)
					}
					found = true
				}
			}
			if !found {
				t.Fatalf("no signed %s receipt with %q", wantVerdict, marker)
			}
		})
	}
}

func TestWatchA2AResponseCeilingRemainsObservation(t *testing.T) {
	cfg := config.Defaults()
	cfg.WatchOnly, cfg.A2AScanning.Enabled = true, true
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	body := "{\"text\":\"" + strings.Repeat("ordinary ", 100) + "\"}"
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.vendor.example/message:send", nil)
	req.Header.Set("Content-Type", "application/a2a+json")
	resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req, Body: io.NopCloser(strings.NewReader(body))}
	err := watchResponseBody(t.Context(), resp, watchResponseOptions{Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New(), MaxBytes: 32})
	if err != nil {
		t.Fatalf("response ceiling enforced: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != body {
		t.Fatalf("response changed: %q %v", got, err)
	}
}

// Reuse the audit-mode fixtures and actual transport entry points. Fetch
// consumes a target URL, CONNECT consumes authority/headers, and WebSocket
// bodies are frames; HTTP body fixtures do not apply to those handshakes.
func TestWatchAuditFloorTransportParity(t *testing.T) {
	surfaces := map[string][]string{
		"fetch": {"url"}, "forward": {"url", "header", "body"},
		"intercept": {"url", "header", "body"}, "reverse": {"url", "header", "body"},
		"websocket": {"url", "header", "body"}, "connect": {"header"},
	}
	for transport, list := range surfaces {
		for _, surface := range list {
			t.Run(transport+"/"+surface, func(t *testing.T) {
				for _, watch := range []bool{false, true} {
					got := driveAuditFloor(t, transport, "core", surface, false, watch)
					if !got.blocked || got.hits != 0 {
						t.Fatalf("watch=%t lost audit floor: %+v", watch, got)
					}
				}
			})
		}
	}
}

func TestWatchAuditFloorURLTransportParity(t *testing.T) {
	for _, query := range []string{"q=" + percentNested("hello", 501), watchQueryLimitFixture()} {
		for _, surface := range []string{TransportFetch, TransportWS} {
			for _, watch := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/watch=%t/querybytes=%d", surface, watch, len(query)), func(t *testing.T) {
					var hits atomic.Int32
					upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						hits.Add(1)
						w.WriteHeader(http.StatusOK)
					}))
					defer upstream.Close()
					configure := func(cfg *config.Config) { auditFloorConfig(false, "")(cfg); cfg.WatchOnly = watch }
					if surface == TransportWS {
						addr, cleanup := setupWSProxy(t, configure)
						defer cleanup()
						conn, err := dialWSConnToTarget(addr, "ws"+strings.TrimPrefix(upstream.URL, "http")+"/?"+query)
						if conn != nil {
							_ = conn.Close()
						}
						if err == nil || hits.Load() != 0 {
							t.Fatalf("URL floor lost: err=%v hits=%d", err, hits.Load())
						}
						return
					}
					_, p, cleanup := setupForwardProxyWithInstance(t, configure)
					defer cleanup()
					out := httptest.NewRecorder()
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL+"/?"+query), nil)
					p.handleFetch(out, req)
					if out.Code != http.StatusForbidden || hits.Load() != 0 {
						t.Fatalf("URL floor lost: status=%d hits=%d", out.Code, hits.Load())
					}
				})
			}
		}
	}
}
