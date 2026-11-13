// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// TestAuditModeConnectSNIRequireTLS records the opaque-tunnel refusal.
// After the dial and the 200, SNIRequireTLSEnabled closes the tunnel for a
// ClientHello without a matching SNI and for a payload that is not TLS.
// That check does not read enforce, so both settings drop the bytes.
func TestAuditModeConnectSNIRequireTLS(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce=%t", enforce), func(t *testing.T) {
			for _, payload := range [][]byte{buildClientHello("other.vendor.example"), []byte("not TLS")} {
				upstream := listenEcho(t)
				t.Cleanup(func() { _ = upstream.Close() })
				proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
					cfg.Enforce = &enforce
					cfg.ForwardProxy.SNIRequireTLS = ptrBool(true)
				})
				t.Cleanup(cleanup)
				conn := dialProxy(t, proxyAddr)
				t.Cleanup(func() { _ = conn.Close() })
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
				// Only a closed connection counts as the refusal: end of stream,
				// or a reset when the proxy closes with client bytes unread. A
				// timeout or any other error means the tunnel stayed open.
				closed := errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)
				if n != 0 || !closed {
					t.Fatalf("authority failure relayed %d bytes, read err=%v", n, err)
				}
			}
		})
	}
}

// TestAuditModeEnvelopeSignsFetch records a clean fetch. The outbound
// request carries a mediation envelope when the emitter is installed.
// A clean URL does not consult enforce, so both settings deliver the header.
func TestAuditModeEnvelopeSignsFetch(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce=%t", enforce), func(t *testing.T) {
			var header atomic.Value
			backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				header.Store(r.Header.Get(envelope.HeaderName))
				_, _ = io.WriteString(w, "ok")
			}))
			t.Cleanup(backend.Close)
			_, p, cleanup := setupForwardProxyWithInstance(t, func(c *config.Config) {
				c.Enforce = &enforce
				c.MediationEnvelope.Enabled = true
			})
			t.Cleanup(cleanup)
			p.envelopeEmitterPtr.Store(envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash}))
			w := httptest.NewRecorder()
			p.handleFetch(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.example/fetch?url="+url.QueryEscape(backend.URL), nil))
			if got, _ := header.Load().(string); w.Code != http.StatusOK || got == "" {
				t.Fatalf("fetch upstream received no envelope: status=%d body=%s", w.Code, w.Body)
			}
		})
	}
}

// TestAuditModeURLInspectionFloor records decoder and query-value bounds.
// A percent-encoding chain past the decoder ceiling is a core-floor URL
// result, and 112 query values hit the same core query-value limit. Fetch
// and WebSocket both refuse them through urlResultBlocks. Enforce does not
// release that floor, and the upstream is not called for either setting.
func TestAuditModeURLInspectionFloor(t *testing.T) {
	queries := []string{"q=" + percentNested("hello", 501), auditQueryLimitFixture()}
	for _, enforce := range []bool{false, true} {
		for _, query := range queries {
			for _, surface := range []string{TransportFetch, TransportWS} {
				t.Run(fmt.Sprintf("enforce=%t/%s/querybytes=%d", enforce, surface, len(query)), func(t *testing.T) {
					var hits atomic.Int32
					upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						hits.Add(1)
						w.WriteHeader(http.StatusOK)
					}))
					t.Cleanup(upstream.Close)
					configure := auditFloorConfig(enforce, "")
					if surface == TransportWS {
						addr, cleanup := setupWSProxy(t, configure)
						t.Cleanup(cleanup)
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
					t.Cleanup(cleanup)
					out := httptest.NewRecorder()
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL+"/?"+query), nil)
					p.handleFetch(out, req)
					if out.Code != http.StatusForbidden || hits.Load() != 0 {
						t.Fatalf("URL floor lost: status=%d hits=%d body=%s", out.Code, hits.Load(), out.Body.String())
					}
				})
			}
		}
	}
}

func auditQueryLimitFixture() string {
	q := make([]string, 112)
	for i := range q {
		q[i] = fmt.Sprintf("a%d=%d", i, i%10)
	}
	return strings.Join(q, "&")
}

// TestAuditModeWebSocketNegotiationFloor records a completed handshake
// that forwards Sec-WebSocket-Protocol or Sec-WebSocket-Extensions.
// A benign text frame is echoed. A core credential in a later text frame
// is a hard block in the relay, so it is not echoed. Neither decision
// reads enforce.
func TestAuditModeWebSocketNegotiationFloor(t *testing.T) {
	for _, header := range []string{"Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
		for _, enforce := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/enforce=%t", header, enforce), func(t *testing.T) {
				backend, closeBackend := wsEchoServer(t)
				t.Cleanup(closeBackend)
				addr, cleanup := setupWSProxy(t, func(cfg *config.Config) {
					cfg.Enforce = &enforce
				})
				t.Cleanup(cleanup)
				value := "agent-stream"
				if header == "Sec-WebSocket-Extensions" {
					value = "permessage-deflate"
				}
				conn, err := dialWSConnWithHeader(addr, backend, http.Header{header: []string{value}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(testWSHello)); err != nil {
					t.Fatal(err)
				}
				if got, _, err := wsutil.ReadServerData(conn); err != nil || string(got) != testWSHello {
					t.Fatalf("benign frame: %q %v", got, err)
				}
				credential := "AKIA" + "IOSFODNN7" + testWSExample
				if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(credential)); err != nil {
					t.Fatal(err)
				}
				if got, _, err := wsutil.ReadServerData(conn); err == nil {
					t.Fatalf("negotiation bypass forwarded credential: %q", got)
				}
			})
		}
	}
}

// TestAuditModeWebSocketAccessFloor records handshake admission that
// does not read enforce. A disabled proxy returns before the dial. A full
// connection semaphore refuses. RequireReceipts with no emitter refuses.
// Both enforce settings fail the handshake.
func TestAuditModeWebSocketAccessFloor(t *testing.T) {
	for _, reason := range []string{"disabled", "capacity", "receipts"} {
		for _, enforce := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/enforce=%t", reason, enforce), func(t *testing.T) {
				backend, closeBackend := wsEchoServer(t)
				t.Cleanup(closeBackend)
				addr, cleanup := setupWSProxy(t, func(cfg *config.Config) {
					cfg.Enforce = &enforce
					cfg.WebSocketProxy.Enabled = reason != "disabled"
					cfg.FlightRecorder.RequireReceipts = reason == "receipts"
				})
				t.Cleanup(cleanup)
				if reason == "capacity" {
					sem := getWSSemaphore(128)
					held := 0
					for sem.TryAcquire() {
						held++
					}
					t.Cleanup(func() {
						for range held {
							sem.Release()
						}
					})
				}
				conn, err := dialWSConn(addr, backend)
				if conn != nil {
					_ = conn.Close()
				}
				if err == nil {
					t.Fatalf("%s guard allowed the handshake", reason)
				}
			})
		}
	}
}

// TestAuditModeWebSocketHeaderAllowlist records buildWSForwardHeaders.
// Proxy-Authorization, a private header, and Cookie are dropped.
// Authorization is copied. The function does not read enforce, so both
// settings produce the same header set.
func TestAuditModeWebSocketHeaderAllowlist(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce=%t", enforce), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Enforce = &enforce
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.example/ws", nil)
			req.Header.Set("Proxy-Authorization", "Basic proxy-only")
			req.Header.Set("X-Private-Header", "local-only")
			req.Header.Set("Cookie", "session=private")
			req.Header.Set("Authorization", "Bearer upstream")
			target, err := url.Parse("ws://api.vendor.example/socket")
			if err != nil {
				t.Fatal(err)
			}
			got := (&Proxy{}).buildWSForwardHeaders(req, target, cfg, nil)
			for _, name := range []string{"Proxy-Authorization", "X-Private-Header", "Cookie"} {
				if got.Get(name) != "" {
					t.Errorf("unexpected forwarded %s", name)
				}
			}
			if got.Get("Authorization") != "Bearer upstream" {
				t.Fatal("upstream authorization lost")
			}
		})
	}
}

// TestAuditModeWebSocketOutboundInspectionFloor records relay limits
// that close the socket before delivery. Oversized and fragmented frames
// use MaxMessageBytes. Invalid UTF-8 and a binary frame are refused while
// binary frames are disallowed. Those checks do not read enforce.
func TestAuditModeWebSocketOutboundInspectionFloor(t *testing.T) {
	for _, shape := range []string{"oversized", "fragmented", "invalid_utf8", "binary"} {
		for _, enforce := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/enforce=%t", shape, enforce), func(t *testing.T) {
				backend, _, delivered, done := websocketBoundaryBackend(t)
				addr, cleanup := setupWSProxy(t, func(cfg *config.Config) {
					cfg.Enforce = &enforce
					cfg.WebSocketProxy.MaxMessageBytes = 64
					cfg.WebSocketProxy.AllowBinaryFrames = false
				})
				t.Cleanup(cleanup)
				conn := dialWS(t, addr, backend)
				t.Cleanup(func() { _ = conn.Close() })
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				switch shape {
				case "oversized":
					_ = wsutil.WriteClientMessage(conn, ws.OpText, bytes.Repeat([]byte("padding "), 20))
				case "fragmented":
					writeMaskedClientFrame(t, conn, false, ws.OpText, []byte(strings.Repeat("a", 40)))
					writeMaskedClientFrame(t, conn, true, ws.OpContinuation, []byte(strings.Repeat("b", 40)))
				case "invalid_utf8":
					_ = wsutil.WriteClientMessage(conn, ws.OpText, []byte{0xff, 0xfe})
				case "binary":
					_ = wsutil.WriteClientMessage(conn, ws.OpBinary, []byte("uninspectable"))
				}
				if got, _, err := wsutil.ReadServerData(conn); err == nil {
					t.Fatalf("outbound inspection guard released %q", got)
				}
				assertWebSocketBoundaryBackendReceivedNothing(t, delivered, done)
			})
		}
	}
}

// TestAuditModeWebSocketUnavailableScanner records a closed scanner.
// pinResolvedScanner refuses the handshake before the upstream dial.
// That refusal does not read enforce.
func TestAuditModeWebSocketUnavailableScanner(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce=%t", enforce), func(t *testing.T) {
			backend, closeBackend := wsEchoServer(t)
			t.Cleanup(closeBackend)
			addr, p, cleanup := setupWSProxyDefaultWithProxy(t, func(cfg *config.Config) {
				cfg.Enforce = &enforce
			})
			t.Cleanup(cleanup)
			p.scannerPtr.Load().Close()
			conn, err := dialWSConnWithHeader(addr, backend, http.Header{"Sec-WebSocket-Protocol": []string{"agent-stream"}})
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil {
				t.Fatal("unavailable scanner allowed the connection")
			}
		})
	}
}

// TestAuditModeWebSocketMalformedNegotiation records a client that sets a
// subprotocol header and omits the upgrade handshake. The HTTP upgrader
// writes the error and the upstream handshake count stays zero. The
// upgrader does not read enforce.
func TestAuditModeWebSocketMalformedNegotiation(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce=%t", enforce), func(t *testing.T) {
			backend, handshakes, _, _ := websocketBoundaryBackend(t)
			addr, cleanup := setupWSProxy(t, func(cfg *config.Config) {
				cfg.Enforce = &enforce
			})
			t.Cleanup(cleanup)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/ws?url=ws://"+backend, nil)
			req.RequestURI = ""
			req.Header.Set("Sec-WebSocket-Protocol", "agent-stream")
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = response.Body.Close() })
			if handshakes.Load() != 0 {
				t.Fatalf("malformed client initiated %d upstream handshakes", handshakes.Load())
			}
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status=%d", response.StatusCode)
			}
		})
	}
}
