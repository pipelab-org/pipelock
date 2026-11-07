// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// Real transports run on the main listener and on a registered listener whose
// BaseContext is independent of Start. The latter needs the gate's own cancel,
// not merely cancellation inherited from the run context.
func TestServer_HijackedDrainSeal(t *testing.T) {
	for _, transport := range []string{"connect", "intercept", "websocket"} {
		for _, listener := range []string{"main", "agent", "held_agent"} {
			t.Run(transport+"/"+listener, func(t *testing.T) {
				dir, cfgPath, roots := hijackDrainConfig(t, transport == "intercept")
				s, log := newTestServerForStart(t, func(o *ServerOpts) {
					o.ConfigFile = cfgPath
					o.Listen = serverTestEphemeralListen
					o.ListenChanged = true
				})
				released, unwound := make(chan struct{}), make(chan struct{})
				var once sync.Once
				release := func() { once.Do(func() { close(released) }) }
				t.Cleanup(release)
				var address string
				if listener != "main" {
					h := s.proxy.Handler()
					agent := newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						h.ServeHTTP(w, r)
						close(unwound)
						if listener == "held_agent" {
							<-released
						}
					}))
					// Start's final cleanup repeats the drain. Release only then,
					// proving the initial deadline was preserved as an error.
					var shutdowns atomic.Int32
					agent.RegisterOnShutdown(func() {
						if shutdowns.Add(1) == 2 {
							release()
						}
					})
					ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", serverTestEphemeralListen)
					if err != nil {
						t.Fatal(err)
					}
					address = ln.Addr().String()
					s.proxy.RegisterAgentServer(agent)
					t.Cleanup(func() { _ = agent.Close() })
					go func() { _ = agent.Serve(ln) }()
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := startDrainLifecycle(t, cancel, release, func() error { return s.Start(ctx) })
				mainAddr := drainListenerAddress(t, log, "  Listen: ")
				if address == "" {
					address = mainAddr
				}
				conn, upstreamClosed := openDrainTransport(t, address, transport, roots)
				defer func() { _ = conn.Close() }()
				cancel()
				if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Read(make([]byte, 1)); err == nil {
					t.Fatal("shutdown left client tunnel open")
				} else {
					var ne net.Error
					if errors.As(err, &ne) && ne.Timeout() {
						t.Fatal("shutdown did not close client tunnel before grace expired")
					}
				}
				awaitDrainSignal(t, upstreamClosed, "upstream tunnel close")
				err := awaitDrainResult(t, done)
				incomplete := listener == "held_agent"
				assertDrainResult(t, err, incomplete, "")
				if listener != "main" {
					awaitDrainSignal(t, unwound, "hijacked handler completion")
				}
				assertDrainEvidence(t, dir, incomplete, false)
				wantTransport := "connect"
				if transport == "websocket" {
					wantTransport = "websocket"
				}
				assertHijackOutcomeBeforeSeal(t, dir, s.cfg.FlightRecorder.SigningKeyPath, wantTransport, !incomplete)
			})
		}
	}
}

func hijackDrainConfig(t *testing.T, intercept bool) (string, string, *x509.CertPool) {
	t.Helper()
	dir, cfgPath := drainReceiptConfig(t, 1)
	data, err := os.ReadFile(filepath.Clean(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("  require_receipts: true\ninternal: []\nssrf:\n  ip_allowlist: [127.0.0.0/8]\nforward_proxy:\n  enabled: true\n  sni_verification: false\n  sni_require_tls: false\nwebsocket_proxy:\n  enabled: true\n")...)
	var roots *x509.CertPool
	if intercept {
		ca, key, pem, genErr := certgen.GenerateCA("Test CA", time.Hour)
		if genErr != nil {
			t.Fatal(genErr)
		}
		certPath, keyPath := filepath.Join(t.TempDir(), "ca.pem"), filepath.Join(t.TempDir(), "ca.key")
		if err := certgen.SaveCA(certPath, keyPath, ca, key); err != nil {
			t.Fatal(err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			t.Fatal("test CA not loaded")
		}
		data = append(data, []byte(fmt.Sprintf("tls_interception:\n  enabled: true\n  ca_cert: %s\n  ca_key: %s\n", strconv.Quote(certPath), strconv.Quote(keyPath)))...)
	}
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, cfgPath, roots
}

func openDrainTransport(t *testing.T, address, transport string, roots *x509.CertPool) (net.Conn, <-chan struct{}) {
	t.Helper()
	if transport == "websocket" {
		return openDrainWebSocket(t, address)
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", serverTestEphemeralListen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	closed := make(chan struct{})
	accepted := make(chan net.Conn, 1)
	go func() {
		upstream, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- upstream
		defer func() { _ = upstream.Close() }()
		_, _ = io.Copy(io.Discard, upstream)
		close(closed)
	}()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	target := ln.Addr().String()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	responseConn := conn
	t.Cleanup(func() { _ = responseConn.Close(); _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	select {
	case upstream := <-accepted:
		t.Cleanup(func() { _ = upstream.Close() })
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("upstream not accepted")
	}
	if transport == "intercept" {
		tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		conn = tlsConn
	}
	return conn, closed
}

func openDrainWebSocket(t *testing.T, address string) (net.Conn, <-chan struct{}) {
	t.Helper()
	closed := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			t.Errorf("upstream upgrade: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		defer close(closed)
		for {
			msg, op, err := wsutil.ReadClientData(conn)
			if err != nil {
				return
			}
			if err := wsutil.WriteServerMessage(conn, op, msg); err != nil {
				return
			}
		}
	}))
	t.Cleanup(upstream.Close)
	target := "ws" + upstream.URL[len("http"):] + "/stream"
	endpoint := "ws://" + address + "/ws?url=" + url.QueryEscape(target)
	dialer := ws.Dialer{}

	conn, _, _, err := dialer.Dial(t.Context(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	// The round trip proves both relay directions are running before shutdown.
	if err := wsutil.WriteClientText(conn, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err != nil {
		t.Fatal(err)
	}
	return conn, closed
}

func assertHijackOutcomeBeforeSeal(t *testing.T, dir, keyPath, transport string, sealed bool) {
	t.Helper()
	key, err := signing.LoadPrivateKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	outcomes := 0
	for _, path := range paths {
		entries, err := recorder.ReadEntries(path)
		if err != nil {
			t.Fatal(err)
		}
		sawSeal := false
		for _, entry := range entries {
			if entry.Type == "transcript_root" {
				sawSeal = true
			}
			if entry.Type != "action_receipt" {
				continue
			}
			var rcpt receipt.Receipt
			if err := json.Unmarshal(entry.RawDetail, &rcpt); err != nil {
				t.Fatal(err)
			}
			if rcpt.ActionRecord.Transport != transport || rcpt.ActionRecord.DecisionPhase != receipt.DecisionPhaseOutcome {
				continue
			}
			if sawSeal {
				t.Error("outcome written after transcript root")
			}
			if err := receipt.VerifyWithKey(rcpt, pub); err != nil {
				t.Fatalf("outcome signature: %v", err)
			}
			outcomes++
		}
		if sealed && !sawSeal {
			t.Error("missing transcript root in outcome chain")
		}
	}
	if outcomes == 0 {
		t.Fatalf("missing signed %s outcome receipt", transport)
	}
	t.Logf("signature-verified %s outcomes=%d sealed=%t", transport, outcomes, sealed)
}
