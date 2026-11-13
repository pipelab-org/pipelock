// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testWSProtoPreferred = "agent-stream.v2"
	testWSProtoFallback  = "agent-stream.v1"
	testWSProtoUnoffered = "other-stream"
)

// wsSelectingBackend starts an echo backend that selects the first offered
// subprotocol accepted by choose. It records every offer it saw and how many
// handshakes reached it.
func wsSelectingBackend(t *testing.T, choose func(string) bool) (target string, offers func() []string, hits *atomic.Int64) {
	t.Helper()
	var seen atomic.Pointer[[]string]
	hits = &atomic.Int64{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		got := wsProtocolOffers(r.Header)
		seen.Store(&got)
		upgrader := ws.HTTPUpgrader{Protocol: choose}
		conn, _, _, err := upgrader.Upgrade(r, w)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			msg, op, readErr := wsutil.ReadClientData(conn)
			if readErr != nil {
				return
			}
			if writeErr := wsutil.WriteServerMessage(conn, op, msg); writeErr != nil {
				return
			}
		}
	}))
	t.Cleanup(backend.Close)
	offers = func() []string {
		if got := seen.Load(); got != nil {
			return *got
		}
		return nil
	}
	return "ws" + strings.TrimPrefix(backend.URL, "http"), offers, hits
}

func wsProxyURL(proxyAddr, target string) string {
	return "ws://" + proxyAddr + "/ws?url=" + url.QueryEscape(target)
}

// requireWSEcho proves the relay carries frames after the handshake.
func requireWSEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q, want ping", got)
	}
}

func TestWSSubprotocolNegotiation(t *testing.T) {
	tests := []struct {
		name            string
		requireReceipts bool
		// rawOffers are the client's Sec-WebSocket-Protocol header lines.
		rawOffers    []string
		choose       func(string) bool
		wantSelected string
		wantOffers   []string
	}{
		{
			name:         "upstream selects the only offer",
			rawOffers:    []string{testWSProtoPreferred},
			choose:       func(p string) bool { return p == testWSProtoPreferred },
			wantSelected: testWSProtoPreferred,
			wantOffers:   []string{testWSProtoPreferred},
		},
		{
			name:         "upstream selects the second of several offers",
			rawOffers:    []string{testWSProtoPreferred + ", " + testWSProtoFallback},
			choose:       func(p string) bool { return p == testWSProtoFallback },
			wantSelected: testWSProtoFallback,
			wantOffers:   []string{testWSProtoPreferred, testWSProtoFallback},
		},
		{
			name:         "offers on separate header lines all reach the upstream",
			rawOffers:    []string{testWSProtoPreferred, testWSProtoFallback},
			choose:       func(p string) bool { return p == testWSProtoFallback },
			wantSelected: testWSProtoFallback,
			wantOffers:   []string{testWSProtoPreferred, testWSProtoFallback},
		},
		{
			name:         "upstream selects none",
			rawOffers:    []string{testWSProtoPreferred},
			choose:       func(string) bool { return false },
			wantSelected: "",
			wantOffers:   []string{testWSProtoPreferred},
		},
		{
			name:            "required receipts still negotiate",
			requireReceipts: true,
			rawOffers:       []string{testWSProtoPreferred},
			choose:          func(p string) bool { return p == testWSProtoPreferred },
			wantSelected:    testWSProtoPreferred,
			wantOffers:      []string{testWSProtoPreferred},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, offers, _ := wsSelectingBackend(t, tt.choose)
			proxyAddr, p, cleanup := setupWSProxyDefaultWithProxy(t, func(cfg *config.Config) {
				cfg.FlightRecorder.RequireReceipts = tt.requireReceipts
			})
			defer cleanup()
			if tt.requireReceipts {
				p.receiptEmitterPtr.Store(newReceiptProxyHelper(t).emitter)
			}

			resp, conn := rawWSHandshake(t, ws.HandshakeHeaderHTTP(http.Header{headerNameWSProtocol: tt.rawOffers}),
				wsProxyURL(proxyAddr, target), true)
			defer func() { _ = conn.Close() }()

			if resp.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("handshake status = %d, want 101", resp.StatusCode)
			}
			if selected := resp.Header.Get(headerNameWSProtocol); selected != tt.wantSelected {
				t.Fatalf("selected subprotocol = %q, want %q", selected, tt.wantSelected)
			}
			if got := offers(); strings.Join(got, "|") != strings.Join(tt.wantOffers, "|") {
				t.Fatalf("upstream saw offers %q, want %q", got, tt.wantOffers)
			}
			requireWSEcho(t, conn)
		})
	}
}

// wsHandshakeReply is the status line and headers of a handshake response.
type wsHandshakeReply struct {
	StatusCode int
	Header     http.Header
}

// rawWSHandshake writes an upgrade request for target with the given extra
// headers and returns the reply. withKey false omits the
// Sec-WebSocket-Key header to produce an invalid handshake.
func rawWSHandshake(t *testing.T, extra ws.HandshakeHeaderHTTP, target string, withKey bool) (wsHandshakeReply, net.Conn) {
	t.Helper()
	return rawWSHandshakeVersion(t, extra, target, "HTTP/1.1", withKey)
}

// An upstream that selects a subprotocol the client never offered breaks the
// handshake contract. The client must get an HTTP error, not a 101.
func TestWSSubprotocolUpstreamSelectsUnoffered(t *testing.T) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upgrader := ws.HTTPUpgrader{Header: http.Header{headerNameWSProtocol: []string{testWSProtoUnoffered}}}
			conn, _, _, upgradeErr := upgrader.Upgrade(r, w)
			if upgradeErr == nil {
				_ = conn.Close()
			}
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	proxyAddr, cleanup := setupWSProxy(t, nil)
	defer cleanup()

	resp, conn := rawWSHandshake(t, ws.HandshakeHeaderHTTP(http.Header{headerNameWSProtocol: []string{testWSProtoPreferred}}),
		wsProxyURL(proxyAddr, "ws://"+ln.Addr().String()), true)
	defer func() { _ = conn.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}

// A malformed client handshake that offers a subprotocol is refused before
// any upstream connection is made.
func TestWSSubprotocolInvalidClientHandshakeNeverDials(t *testing.T) {
	target, _, hits := wsSelectingBackend(t, func(string) bool { return true })
	proxyAddr, cleanup := setupWSProxy(t, nil)
	defer cleanup()

	resp, conn := rawWSHandshake(t, ws.HandshakeHeaderHTTP(http.Header{headerNameWSProtocol: []string{testWSProtoPreferred}}),
		wsProxyURL(proxyAddr, target), false)
	defer func() { _ = conn.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if got := resp.Header.Get(blockreason.HeaderReason); got != string(blockreason.BadRequest) {
		t.Fatalf("block reason header = %q, want %q", got, blockreason.BadRequest)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("upstream handshakes = %d, want 0", got)
	}
}

// With a subprotocol offer the client is not upgraded until the upstream
// answers, so a refused destination is an HTTP 403 carrying the block reason.
func TestWSSubprotocolRefusedDestinationIsHTTP(t *testing.T) {
	proxyAddr, cleanup := setupWSProxy(t, func(cfg *config.Config) {
		cfg.Internal = []string{"203.0.113.0/24"} // non-nil enables DNS SSRF; core CIDRs are merged.
		cfg.SSRF.IPAllowlist = nil
		cfg.TrustedDomains = []string{"trusted-metadata.test"}
		cfg.DNS.HostOverrides = map[string][]string{"trusted-metadata.test": {"169.254.169.254"}}
	})
	defer cleanup()

	resp, conn := rawWSHandshake(t, ws.HandshakeHeaderHTTP(http.Header{headerNameWSProtocol: []string{testWSProtoPreferred}}),
		wsProxyURL(proxyAddr, "ws://trusted-metadata.test/latest/meta-data/"), true)
	defer func() { _ = conn.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if got := resp.Header.Get(blockreason.HeaderReason); got != string(blockreason.SSRFMetadata) {
		t.Fatalf("block reason header = %q, want %q", got, blockreason.SSRFMetadata)
	}
}

// A secret placed in a later Sec-WebSocket-Protocol line is still scanned:
// every offer is forwarded, so every offer must be inspected.
func TestWSSubprotocolSecondHeaderLineIsScanned(t *testing.T) {
	target, _, hits := wsSelectingBackend(t, func(string) bool { return true })
	proxyAddr, cleanup := setupWSProxy(t, nil)
	defer cleanup()

	secret := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	resp, conn := rawWSHandshake(t, ws.HandshakeHeaderHTTP(http.Header{headerNameWSProtocol: []string{testWSProtoPreferred, secret}}),
		wsProxyURL(proxyAddr, target), true)
	defer func() { _ = conn.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("upstream handshakes = %d, want 0", got)
	}
}

func TestValidateWSClientHandshake(t *testing.T) {
	valid := func() *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.example/ws", nil)
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		return r
	}
	if err := validateWSClientHandshake(valid()); err != nil {
		t.Fatalf("valid handshake rejected: %v", err)
	}
	// The upgrade reads the first Connection line only, so a later line that
	// does not name Upgrade must not fail the pre-check.
	split := valid()
	split.Header.Add("Connection", "keep-alive")
	if err := validateWSClientHandshake(split); err != nil {
		t.Fatalf("handshake with a second Connection line rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"missing key", func(r *http.Request) { r.Header.Del("Sec-WebSocket-Key") }},
		{"wrong version", func(r *http.Request) { r.Header.Set("Sec-WebSocket-Version", "8") }},
		{"missing upgrade", func(r *http.Request) { r.Header.Del("Upgrade") }},
		{"wrong method", func(r *http.Request) { r.Method = http.MethodPost }},
		{"http/1.0", func(r *http.Request) {
			r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/1.0", 1, 0
		}},
		{"missing host", func(r *http.Request) { r.Host = "" }},
		{"upgrade only on a later connection line", func(r *http.Request) {
			r.Header["Connection"] = []string{"keep-alive", "Upgrade"}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := valid()
			tt.mutate(r)
			err := validateWSClientHandshake(r)
			if err == nil || errors.Is(err, errWSHandshakeValidated) {
				t.Fatalf("invalid handshake accepted: %v", err)
			}
		})
	}
}

// A long offer list and a Connection header that also carries keep-alive
// are legal handshakes. The pre-upgrade check must accept both.
func TestValidateWSClientHandshakeAcceptsLongOfferList(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.example/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "keep-alive, Upgrade")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	offers := make([]string, 0, 800)
	for i := range 800 {
		offers = append(offers, fmt.Sprintf("agent-stream.v%d", i))
	}
	r.Header.Set(headerNameWSProtocol, strings.Join(offers, ", "))
	if err := validateWSClientHandshake(r); err != nil {
		t.Fatalf("long offer list rejected: %v", err)
	}
}

// HTTP/1.0 can reach the handler. The pre-upgrade check must refuse it
// before any upstream dial: the client upgrade rejects that version.
func TestWSSubprotocolHTTP10DoesNotDial(t *testing.T) {
	target, _, hits := wsSelectingBackend(t, func(string) bool { return true })
	proxyAddr, cleanup := setupWSProxy(t, nil)
	defer cleanup()

	// keep-alive stops net/http from rewriting Connection to "close", which would
	// fail the re-parse for a different reason. This is the handshake whose
	// version Request.Write turns into HTTP/1.1.
	extra := ws.HandshakeHeaderHTTP(http.Header{
		headerNameWSProtocol: []string{testWSProtoPreferred},
		"Connection":         []string{"keep-alive, Upgrade"},
	})
	resp, conn := rawWSHandshakeVersion(t, extra, wsProxyURL(proxyAddr, target), "HTTP/1.0", true)
	defer func() { _ = conn.Close() }()
	if resp.StatusCode != http.StatusBadRequest || hits.Load() != 0 {
		t.Fatalf("status = %d, want %d; upstream handshakes = %d, want 0",
			resp.StatusCode, http.StatusBadRequest, hits.Load())
	}
}

// rawWSHandshakeVersion is rawWSHandshake with the request version chosen by
// the caller. HTTP/1.0 is a version the net/http server delivers to the handler.
func rawWSHandshakeVersion(t *testing.T, extra ws.HandshakeHeaderHTTP, target, proto string, withKey bool) (wsHandshakeReply, net.Conn) {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	var d net.Dialer
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp4", u.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s %s\r\nHost: %s\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n", u.RequestURI(), proto, u.Host)
	if http.Header(extra).Get("Connection") == "" {
		b.WriteString("Connection: Upgrade\r\n")
	}
	if withKey {
		b.WriteString("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
	}
	for name, values := range http.Header(extra) {
		for _, v := range values {
			fmt.Fprintf(&b, "%s: %s\r\n", name, v)
		}
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		_ = conn.Close()
		t.Fatalf("write handshake: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read handshake response: %v", err)
	}
	// A handshake reply carries no body the tests read.
	_ = resp.Body.Close()
	return wsHandshakeReply{StatusCode: resp.StatusCode, Header: resp.Header}, conn
}

// A client whose upgrade is refused has already been hijacked from the HTTP
// server, so the handler must close the connection itself.
func TestWSFailedClientUpgradeClosesConnection(t *testing.T) {
	target, _, hits := wsSelectingBackend(t, func(string) bool { return true })
	proxyAddr, cleanup := setupWSProxy(t, nil)
	defer cleanup()

	resp, conn := rawWSHandshake(t, nil, wsProxyURL(proxyAddr, target), false)
	defer func() { _ = conn.Close() }()
	if resp.StatusCode != http.StatusBadRequest || hits.Load() != 0 {
		t.Fatalf("status = %d, want %d; upstream handshakes = %d, want 0",
			resp.StatusCode, http.StatusBadRequest, hits.Load())
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read after refused upgrade = %v, want EOF", err)
	}
}
