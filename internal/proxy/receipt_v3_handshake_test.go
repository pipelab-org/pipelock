// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

func TestV3RawHandshakeFailure(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("websocket/required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportWS, required, nil)
			var hits atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(upstream.Close)
			target := "ws" + strings.TrimPrefix(upstream.URL, "http")
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ws?url="+target, nil)
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set("Sec-WebSocket-Version", "13")
			// ResponseRecorder doesn't implement Hijacker.
			observer := httptest.NewRecorder()
			p.handleWebSocket(observer, req)
			if hits.Load() != 0 || observer.Code == http.StatusSwitchingProtocols {
				t.Fatalf("failed upgrade released an effect: status=%d hits=%d", observer.Code, hits.Load())
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			assertHandshakeOutcome(t, dir, boundaryUpstreamSend, "not_released")
		})
		t.Run(fmt.Sprintf("connect/required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportConnect, required, nil)
			target, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = target.Close() })
			upstreamBytes := make(chan int, 1)
			go func() {
				conn, err := target.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				payload, _ := io.ReadAll(conn)
				upstreamBytes <- len(payload)
			}()
			client, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			t.Cleanup(func() { _ = client.Close() })
			conn := &v3BrokenHandshakeConn{Conn: client}
			w := &v3HandshakeHijacker{ResponseRecorder: httptest.NewRecorder(), conn: conn}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, target.Addr().String(), nil)
			p.handleConnect(w, req)
			select {
			case n := <-upstreamBytes:
				if n != 0 {
					t.Fatalf("relay sent %d bytes after failed CONNECT handshake", n)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("upstream observer did not finish")
			}
			if conn.writes != 1 {
				t.Fatalf("CONNECT write attempts = %d, want 1", conn.writes)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			assertHandshakeOutcome(t, dir, boundaryDownstreamDelivery, "attempt_unknown")
		})
	}
}

func assertHandshakeOutcome(t *testing.T, dir, boundary, outcome string) {
	t.Helper()
	assertV3BoundaryPair(t, readV3TransportActions(t, dir), boundary, "", outcome)
}

func assertV3BoundaryPair(t *testing.T, actions []v3.Action, boundary, layer, outcome string) {
	t.Helper()
	var actionID, outcomeID string
	intents, outcomes := 0, 0
	for _, action := range actions {
		if action.EffectBoundary != boundary || (layer != "" && action.Layer != layer) {
			continue
		}
		if action.Phase == "intent" {
			actionID = action.ActionID
			intents++
		}
		if action.Phase == "outcome" {
			if action.OutcomeClass != outcome {
				t.Fatalf("unexpected outcome at %s: %+v", boundary, action)
			}
			outcomeID = action.ActionID
			outcomes++
		}
	}
	if intents != 1 || outcomes != 1 || actionID != outcomeID {
		t.Fatalf("%s has %d intents and %d outcomes, want one each", boundary, intents, outcomes)
	}
}

type v3BrokenHandshakeConn struct {
	net.Conn
	writes int
}

func (c *v3BrokenHandshakeConn) Write([]byte) (int, error) {
	c.writes++
	return 0, errors.New("handshake write failed")
}

type v3HandshakeHijacker struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w *v3HandshakeHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(strings.NewReader("example")), bufio.NewWriter(w.conn)), nil
}

func TestV3ReverseUpgradeRefusal(t *testing.T) {
	for _, required := range []bool{false, true} {
		for _, passThrough := range []bool{false, true} {
			t.Run(fmt.Sprintf("required=%t/pass_through=%t", required, passThrough), func(t *testing.T) {
				p, writer, dir, keys := newTestV3HTTPProxy(t, TransportReverse, required, nil)
				var upgrades atomic.Int64
				backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					conn, _, _, err := ws.UpgradeHTTP(r, w)
					if err == nil {
						upgrades.Add(1)
						_ = conn.Close()
					}
				}))
				t.Cleanup(backend.Close)
				target, err := url.Parse(backend.URL)
				if err != nil {
					t.Fatal(err)
				}
				reverse := NewReverseProxy(target, p.ConfigPtr(), p.ScannerPtr(), audit.NewNop(), metrics.New(), nil, nil, nil)
				reverse.SetOwnerProxy(p)
				if passThrough {
					// Exercise delivery when response scanning leaves the upgrade body intact.
					reverse.proxy.ModifyResponse = nil
				}
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				req.Header.Set("Sec-WebSocket-Version", "13")
				observer := httptest.NewRecorder()
				reverse.ServeHTTP(observer, req)
				if observer.Code != http.StatusBadGateway || upgrades.Load() != 1 {
					t.Fatalf("expected one upstream upgrade and a downstream gateway error, got %d/%d",
						upgrades.Load(), observer.Code)
				}
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
				if err != nil || result.Verdict != "VALID" {
					t.Fatalf("verification: %+v (%v)", result, err)
				}
				if passThrough {
					assertHandshakeOutcome(t, dir, boundaryDownstreamDelivery, "not_released")
					return
				}
				for _, action := range readV3TransportActions(t, dir) {
					if action.EffectBoundary == boundaryDownstreamDelivery {
						t.Fatalf("synthetic gateway error was associated with an upgrade: %+v", action)
					}
				}
			})
		}
	}
}

func TestV3WebSocketCredentialEffects(t *testing.T) {
	for _, required := range []bool{false, true} {
		for _, tc := range []struct {
			name          string
			carrier       string
			preDial       bool
			reject        bool
			withholdFrame bool
		}{
			{name: "header", carrier: "header"},
			{name: "header pre-dial", carrier: "header", preDial: true},
			{name: "header upstream rejection", carrier: "header", reject: true},
			{name: "url", carrier: "url"},
			{name: "url pre-dial", carrier: "url", preDial: true},
			{name: "frame", carrier: "frame"},
			{name: "frame withheld", carrier: "frame", withholdFrame: true},
		} {
			t.Run(fmt.Sprintf("required=%t/%s", required, tc.name), func(t *testing.T) {
				const host = "127.0.0.1"
				var faults func(string, string) (v3.StreamFile, error)
				if tc.withholdFrame {
					// Opening record, handshake send intent, client upgrade
					// intent/outcome, handshake send outcome, frame batch.
					faults = v3AppendFault(6, false)
				}
				p, writer, dir, keys := newTestV3HTTPProxy(t, TransportWS, required, faults, func(cfg *config.Config) {
					cfg.DLP.Patterns = append(cfg.DLP.Patterns, audienceReceiptTestPattern(host))
					cfg.RequestBodyScanning.Enabled = true
				})
				upstreamSeen := make(chan string, 1)
				var hits atomic.Int64
				upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					switch tc.carrier {
					case "header":
						upstreamSeen <- r.Header.Get("Authorization")
					case "url":
						upstreamSeen <- r.URL.Path
					}
					if tc.reject {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					conn, _, _, err := ws.UpgradeHTTP(r, w)
					if err != nil {
						t.Error(err)
						return
					}
					defer func() { _ = conn.Close() }()
					if tc.carrier == "frame" {
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						msg, err := wsutil.ReadClientText(conn)
						if err != nil {
							if tc.withholdFrame {
								upstreamSeen <- ""
							} else {
								t.Error(err)
							}
							return
						}
						upstreamSeen <- string(msg)
						if err := wsutil.WriteServerMessage(conn, ws.OpText, []byte("ack")); err != nil {
							t.Error(err)
						}
					}
				}))
				t.Cleanup(upstream.Close)
				p.dialer = v3ObserverDialer{addr: upstream.Listener.Addr().String()}
				roots := x509.NewCertPool()
				roots.AddCert(upstream.Certificate())
				p.wsTLSConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
				target := "wss://" + host + "/socket"
				want := audienceReceiptTestCredential
				header := make(http.Header)
				switch tc.carrier {
				case "header":
					want = "Bearer " + want
					header.Set("Authorization", want)
				case "url":
					want = "/" + want
					target = "wss://" + host + want
				}
				requestPath := "/ws?url=" + url.QueryEscape(target)
				outcome := "completed"
				if tc.preDial {
					outcome = "not_released"
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestPath, nil)
					req.Header = header
					req.Header.Set("Upgrade", "websocket")
					req.Header.Set("Connection", "Upgrade")
					req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
					req.Header.Set("Sec-WebSocket-Version", "13")
					observer := httptest.NewRecorder()
					p.handleWebSocket(observer, req)
					if observer.Code == http.StatusSwitchingProtocols || hits.Load() != 0 {
						t.Fatalf("pre-dial refusal status=%d upstream hits=%d", observer.Code, hits.Load())
					}
				} else {
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					done := make(chan struct{})
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						defer close(done)
						p.handleWebSocket(w, r)
					}))
					t.Cleanup(server.Close)
					dialer := ws.Dialer{Header: ws.HandshakeHeaderHTTP(header)}
					conn, reader, _, err := dialer.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+requestPath)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = conn.Close() }()
					var downstream io.ReadWriter = conn
					if reader != nil {
						defer ws.PutReader(reader)
						downstream = struct {
							io.Reader
							io.Writer
						}{reader, conn}
					}
					if tc.carrier == "frame" {
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(want)); err != nil {
							t.Fatal(err)
						}
						msg, err := wsutil.ReadServerText(downstream)
						if tc.withholdFrame {
							if err == nil {
								t.Fatal("downstream received a frame after withholding")
							}
							want, outcome = "", "not_released"
						} else if err != nil || string(msg) != "ack" {
							t.Fatalf("downstream ack=%q error=%v", msg, err)
						}
					}
					select {
					case seen := <-upstreamSeen:
						if seen != want {
							t.Fatal("upstream carrier did not contain the fixture credential")
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					_ = conn.Close()
					waitForV3Transport(t, done)
				}
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
				if tc.withholdFrame {
					if err != nil || result.Integrity != "ok" || result.Completeness != "end_unproven" {
						t.Fatalf("verification: %+v (%v)", result, err)
					}
					paths, err := filepath.Glob(filepath.Join(dir, "*.receipt-v3.jsonl"))
					if err != nil || len(paths) != 2 {
						t.Fatalf("expected two streams after writer recovery: %v (%v)", paths, err)
					}
					actions := append(readV3TransportFile(t, paths[0]), readV3TransportFile(t, paths[1])...)
					// The failed batch is present in the unconfirmed tail. The
					// successor retains the action ID but omits optional fields
					// such as the credential layer from its repair outcome.
					var supportingID string
					for _, action := range actions {
						if action.Phase == "intent" && action.Layer == credentialAudienceReceiptExtensionKey {
							if supportingID != "" {
								t.Fatal("multiple credential intents in refused frame batch")
							}
							supportingID = action.ActionID
						}
					}
					if supportingID == "" {
						t.Fatal("refused frame batch lacked a supporting intent")
					}
					var pair []v3.Action
					for _, action := range actions {
						if action.ActionID == supportingID {
							pair = append(pair, action)
						}
					}
					assertV3BoundaryPair(t, pair, boundaryUpstreamSend, "", outcome)
					return
				}
				if err != nil || result.Verdict != "VALID" {
					t.Fatalf("verification: %+v (%v)", result, err)
				}
				assertV3BoundaryPair(t, readV3TransportActions(t, dir), boundaryUpstreamSend, credentialAudienceReceiptExtensionKey, outcome)
			})
		}
	}
}
