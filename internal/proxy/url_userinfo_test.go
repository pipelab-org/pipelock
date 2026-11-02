// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobwas/ws"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestURLUserinfoAdmissionBeforeUpstream(t *testing.T) {
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ordinary response")
	}))
	defer backend.Close()
	addr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()
	secret := "gh" + "p_" + strings.Repeat("aB3c", 9)
	random := "Q7mZ9pL4vR2sK8hF6dA0nT5cW3xB1jG" + "uEoYiHkSqVfDtNr"
	for _, transport := range []string{"fetch", "forward"} {
		for name, value := range map[string]string{"hex": hex.EncodeToString([]byte(secret)), "base64": base64.StdEncoding.EncodeToString([]byte(secret)), "base64url": base64.RawURLEncoding.EncodeToString([]byte(secret)), "entropy": random, "benign": "ordinary"} {
			t.Run(transport+"/"+name, func(t *testing.T) {
				u, err := url.Parse(backend.URL + "/read")
				if err != nil {
					t.Fatal(err)
				}
				u.User = url.UserPassword("reader", value)
				before := hits.Load()
				var response *http.Response
				if transport == "fetch" {
					req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/fetch?url="+url.QueryEscape(u.String()), nil)
					if err != nil {
						t.Fatal(err)
					}
					response, err = http.DefaultClient.Do(req)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = conn.Close() }()
					_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.String(), u.Host)
					if err != nil {
						t.Fatal(err)
					}
					response, err = http.ReadResponse(bufio.NewReader(conn), nil)
					if err != nil {
						t.Fatal(err)
					}
				}
				defer func() { _ = response.Body.Close() }()
				_, _ = io.Copy(io.Discard, response.Body)
				if name == "benign" {
					if response.StatusCode != http.StatusOK || hits.Load() != before+1 {
						t.Fatalf("benign request status=%d hits=%d", response.StatusCode, hits.Load()-before)
					}
				} else if response.StatusCode != http.StatusForbidden || hits.Load() != before {
					t.Fatalf("want refusal before upstream, status=%d hits=%d", response.StatusCode, hits.Load()-before)
				}
			})
		}
	}
}

func TestURLUserinfoRecoveredDecodeLimitAudit(t *testing.T) {
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ordinary response")
	}))
	defer backend.Close()
	addr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		enforce := false
		cfg.Enforce = &enforce
		cfg.FetchProxy.Monitoring.Blocklist = []string{"127.0.0.1"}
		cfg.FetchProxy.Monitoring.EntropyThreshold = 0
		cfg.DLP.Patterns = nil
		cfg.RequestBodyScanning.ScanHeaders = false
	})
	defer cleanup()
	deep := base64.StdEncoding.EncodeToString([]byte(percentNested("ordinary", normalize.ScannerQueryUnescapeMaxRounds+20)))
	for _, transport := range []string{"fetch", "forward"} {
		for name, value := range map[string]string{"incomplete": deep, "benign": "ordinary"} {
			t.Run(transport+"/"+name, func(t *testing.T) {
				u, err := url.Parse(backend.URL + "/read")
				if err != nil {
					t.Fatal(err)
				}
				u.User = url.UserPassword("reader", value)
				before := hits.Load()
				var resp *http.Response
				if transport == "fetch" {
					req, requestErr := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/fetch?url="+url.QueryEscape(u.String()), nil)
					if requestErr != nil {
						t.Fatal(requestErr)
					}
					resp, err = http.DefaultClient.Do(req)
				} else {
					conn, dialErr := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
					if dialErr != nil {
						t.Fatal(dialErr)
					}
					defer func() { _ = conn.Close() }()
					_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.String(), u.Host)
					if err == nil {
						resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				want, wantHits := http.StatusForbidden, int32(0)
				if name == "benign" {
					want, wantHits = http.StatusOK, 1
				}
				if resp.StatusCode != want || hits.Load()-before != wantHits {
					t.Fatalf("status=%d hits=%d, want status=%d hits=%d", resp.StatusCode, hits.Load()-before, want, wantHits)
				}
			})
		}
	}
}

func TestWebSocketURLUserinfoAdmission(t *testing.T) {
	var hits atomic.Int32
	authorization := make(chan string, 1)
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		authorization <- r.Header.Get("Authorization")
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer backend.Close()
	addr, cleanup := setupWSProxy(t, func(cfg *config.Config) { cfg.FetchProxy.Monitoring.Blocklist = nil })
	defer cleanup()
	secret := "gh" + "p_" + strings.Repeat("aB3c", 9)
	for _, tc := range []struct {
		name, value string
		block       bool
	}{{"encoded", hex.EncodeToString([]byte(secret)), true}, {"benign", "ordinary", false}} {
		t.Run(tc.name, func(t *testing.T) {
			target, err := url.Parse(strings.Replace(backend.URL, "http://", "ws://", 1))
			if err != nil {
				t.Fatal(err)
			}
			target.User = url.UserPassword("reader", tc.value)
			before := hits.Load()
			conn, err := dialWSConnToTarget(addr, target.String())
			if conn != nil {
				_ = conn.Close()
			}
			if tc.block {
				if err == nil || !strings.Contains(err.Error(), "403") || hits.Load() != before {
					t.Fatalf("refusal err=%v hits=%d", err, hits.Load()-before)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if got := <-authorization; got != "" {
					t.Fatalf("dialer unexpectedly forwarded userinfo as Authorization: %q", got)
				}
			}
		})
	}
}

func TestConnectURLUserinfoAdmission(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer backend.Close()
	addr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()
	secret := "gh" + "p_" + strings.Repeat("aB3c", 9)
	host := strings.TrimPrefix(backend.URL, "http://")
	for _, tc := range []struct {
		target string
		block  bool
	}{{hex.EncodeToString([]byte(secret)) + "@" + host, true}, {host, false}} {
		conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", tc.target, tc.target)
		if err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		_ = conn.Close()
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if tc.block {
			if response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusBadRequest {
				t.Fatalf("invalid authority accepted: %d", response.StatusCode)
			}
		} else if response.StatusCode != http.StatusOK {
			t.Fatalf("benign CONNECT refused: %d", response.StatusCode)
		}
	}
}
