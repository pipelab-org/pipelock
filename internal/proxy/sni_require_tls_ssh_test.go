// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/configs"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cli/presets"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// SSH identification strings: each side of an SSH connection sends one as its
// first bytes (RFC 4253 section 4.2). OpenSSH clients send theirs unprompted.
const (
	sshClientBanner = "SSH-2.0-OpenSSH_9.6\r\n"
	sshServerBanner = "SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu13\r\n"
)

// tunnelUpstream is a raw TCP upstream that optionally speaks first, then
// echoes whatever it receives and reports the total bytes it got from the
// proxy once the proxy closes its side.
type tunnelUpstream struct {
	ln       net.Listener
	received chan []byte
}

func listenTunnelUpstream(t *testing.T, greeting []byte) *tunnelUpstream {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	u := &tunnelUpstream{ln: ln, received: make(chan []byte, 4)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
				if len(greeting) > 0 {
					if _, err := conn.Write(greeting); err != nil {
						u.received <- nil
						return
					}
				}
				var got []byte
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						got = append(got, buf[:n]...)
						_, _ = conn.Write(buf[:n])
					}
					if err != nil {
						u.received <- got
						return
					}
				}
			}()
		}
	}()
	return u
}

// waitReceived returns the bytes the upstream received over the life of one
// tunnel. The upstream only reports once the proxy closes its side.
func (u *tunnelUpstream) waitReceived(t *testing.T) []byte {
	t.Helper()
	select {
	case got := <-u.received:
		return got
	case <-time.After(10 * time.Second):
		t.Fatal("upstream connection was never closed by the proxy")
		return nil
	}
}

// openConnectTunnel issues CONNECT target through the proxy and requires the
// 200 that precedes SNI verification, so a refusal seen later is the tunnel
// gate and not an earlier CONNECT-level block.
func openConnectTunnel(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn := dialProxy(t, proxyAddr)
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		_ = conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	return conn, reader
}

// requireClosedWithoutBytes asserts the proxy closed the tunnel before the
// client deadline: the read ends in EOF or reset rather than timing out, and
// no byte reaches the client.
func requireClosedWithoutBytes(t *testing.T, conn net.Conn, reader *bufio.Reader, wait time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	got, err := io.ReadAll(reader)
	if len(got) > 0 {
		t.Fatalf("refused tunnel relayed %d byte(s) to the client: %q", len(got), got)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("tunnel was left open (read timed out after %v); want proxy-side close", wait)
	}
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("unexpected tunnel read error: %v", err)
	}
}

// auditEvents returns the name of every audit event in the log, plus the
// category of every sni_mismatch event.
func auditEvents(t *testing.T, logPath string) (events, sniCategories []string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry struct {
			Event    string `json:"event"`
			Category string `json:"category"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("parse audit line %q: %v", line, err)
		}
		events = append(events, entry.Event)
		if entry.Event == string(audit.EventSNIMismatch) {
			sniCategories = append(sniCategories, entry.Category)
		}
	}
	return events, sniCategories
}

// loadShippedProfile returns the runtime config for a built-in preset, loaded
// the same way the runtime loads generated preset YAML.
func loadShippedProfile(t *testing.T, name string) *config.Config {
	t.Helper()
	data, ok := configs.Preset(name)
	if !ok {
		t.Fatalf("missing embedded preset %q", name)
	}
	cfg, err := config.LoadPolicyBundleBytes(data)
	if err != nil {
		t.Fatalf("load preset %q: %v", name, err)
	}
	return cfg
}

// TestSNIRequireTLS_SSHBannerOverConnect pins that an SSH client banner sent
// as the first tunnel bytes after CONNECT is refused whenever sni_require_tls
// is true, under every shipped profile. The client-first direction is the one
// the gate inspects: verification peeks the first client bytes. Each profile
// also gets a TLS-with-SNI positive control.
func TestSNIRequireTLS_SSHBannerOverConnect(t *testing.T) {
	type row struct {
		name       string
		tlsHello   bool // send a ClientHello with SNI instead of the banner
		wantRefuse bool
	}
	for _, profile := range presets.All {
		rows := []row{
			{name: "ssh banner refused", wantRefuse: true},
			{name: "tls clienthello with sni passes", tlsHello: true},
		}
		for _, tc := range rows {
			t.Run(profile+"/"+tc.name, func(t *testing.T) {
				upstream := listenTunnelUpstream(t, nil)
				logPath := filepath.Join(t.TempDir(), "audit.jsonl")
				logger, err := audit.New("json", "file", logPath, true, true)
				if err != nil {
					t.Fatalf("audit.New: %v", err)
				}
				proxyAddr, _, cleanup := setupForwardProxyWithLogger(t, logger, func(cfg *config.Config) {
					// Clone resets the policy-hash cache Load warmed, so the
					// harness edits below are not hidden behind a stale hash.
					*cfg = *loadShippedProfile(t, profile).Clone()
					// Harness normalization only: reach a loopback upstream and
					// keep the raw-splice path under test. Nothing here touches
					// SNI settings except turning sni_require_tls on.
					cfg.Internal = nil
					cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
					cfg.APIAllowlist = nil
					cfg.ForwardProxy.Enabled = true
					// Both tunnel timers are far longer than the 3s client
					// deadline below, so a close seen inside that deadline is
					// the refusal teardown and not a timer firing.
					cfg.ForwardProxy.MaxTunnelSeconds = 60
					cfg.ForwardProxy.IdleTimeoutSeconds = 30
					cfg.TLSInterception.Enabled = false
					cfg.ForwardProxy.SNIRequireTLS = ptrBool(true)
				})
				closed := false
				shutdown := func() {
					if !closed {
						closed = true
						cleanup()
						logger.Close()
					}
				}
				defer shutdown()

				target := upstream.ln.Addr().String()
				host, _, err := net.SplitHostPort(target)
				if err != nil {
					t.Fatalf("split target: %v", err)
				}
				payload := []byte(sshClientBanner)
				if tc.tlsHello {
					payload = buildClientHello(host)
				}

				conn, reader := openConnectTunnel(t, proxyAddr, target)
				defer func() { _ = conn.Close() }()
				if _, err := conn.Write(payload); err != nil {
					t.Fatalf("write tunnel payload: %v", err)
				}

				if tc.wantRefuse {
					requireClosedWithoutBytes(t, conn, reader, 3*time.Second)
					if got := upstream.waitReceived(t); len(got) != 0 {
						t.Fatalf("refused tunnel leaked %d byte(s) upstream: %q", len(got), got)
					}
					shutdown()
					events, cats := auditEvents(t, logPath)
					if !slices.Equal(cats, []string{sniCategoryNotTLS}) {
						t.Fatalf("sni_mismatch audit categories = %q, want exactly [%q]", cats, sniCategoryNotTLS)
					}
					if slices.Contains(events, string(audit.EventTunnelOpen)) {
						t.Fatalf("refused tunnel wrote a %s audit event: %q", audit.EventTunnelOpen, events)
					}
					return
				}

				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				echo := make([]byte, len(payload))
				if _, err := io.ReadFull(reader, echo); err != nil {
					t.Fatalf("tunnel did not relay payload round trip: %v", err)
				}
				if !bytes.Equal(echo, payload) {
					t.Fatalf("tunnel echo = %q, want %q", echo, payload)
				}
				_ = conn.Close()
				if got := upstream.waitReceived(t); !bytes.Equal(got, payload) {
					t.Fatalf("upstream received %q, want %q", got, payload)
				}
				shutdown()
				events, cats := auditEvents(t, logPath)
				if !slices.Contains(events, string(audit.EventTunnelOpen)) {
					t.Fatalf("allowed tunnel wrote no %s audit event (events %q); audit capture broken?", audit.EventTunnelOpen, events)
				}
				if len(cats) != 0 {
					t.Fatalf("allowed tunnel logged sni_mismatch categories %q", cats)
				}
			})
		}
	}
}

// TestSNIRequireTLS_SSHServerSpeaksFirst documents current behaviour when the
// upstream speaks first: it sends its SSH banner and the client sends nothing.
// With sni_require_tls on, the silent client is closed by SNI verification's
// read timeout and nothing is relayed in either direction.
func TestSNIRequireTLS_SSHServerSpeaksFirst(t *testing.T) {
	upstream := listenTunnelUpstream(t, []byte(sshServerBanner))
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", logPath, true, true)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	proxyAddr, _, cleanup := setupForwardProxyWithLogger(t, logger, func(cfg *config.Config) {
		cfg.ForwardProxy.SNIRequireTLS = ptrBool(true)
	})
	closed := false
	shutdown := func() {
		if !closed {
			closed = true
			cleanup()
			logger.Close()
		}
	}
	defer shutdown()

	conn, reader := openConnectTunnel(t, proxyAddr, upstream.ln.Addr().String())
	defer func() { _ = conn.Close() }()
	requireClosedWithoutBytes(t, conn, reader, sniReadTimeoutDefault+3*time.Second)
	if got := upstream.waitReceived(t); len(got) != 0 {
		t.Fatalf("silent client tunnel sent %d byte(s) upstream: %q", len(got), got)
	}
	shutdown()
	events, cats := auditEvents(t, logPath)
	if !slices.Equal(cats, []string{sniCategoryTimeout}) {
		t.Fatalf("sni_mismatch audit categories = %q, want exactly [%q]", cats, sniCategoryTimeout)
	}
	if slices.Contains(events, string(audit.EventTunnelOpen)) {
		t.Fatalf("refused tunnel wrote a %s audit event: %q", audit.EventTunnelOpen, events)
	}
}
