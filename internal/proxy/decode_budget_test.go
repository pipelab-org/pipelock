// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Under the race detector keep modest delivery cases for each encoding and
// transport; the full sizes run in TestDecodeBudgetLargeForwardJSONBody,
// TestDecodeBudgetLargeForwardHexBody, TestDecodeBudgetLargeForwardBase64Body
// and their WebSocket counterparts in normal builds. Scanner decode-budget
// tests retain the recursive refusal and large-first-layer boundary coverage.
func decodeBudgetBody(name string) (string, string) {
	const raceBodyBytes = 128 * 1024
	switch name {
	case "json":
		size := 5_240_000
		if raceEnabled {
			size = raceBodyBytes
		}
		return `{"message":"` + strings.Repeat("!", size-20) + `\u0061"}`, "application/json"
	case "hex":
		size := 3 * 1024 * 1024
		if raceEnabled {
			size = raceBodyBytes
		}
		return strings.Repeat("21", size/2), "text/plain"
	case "base64":
		size := 9 * 1024 * 1024
		if raceEnabled {
			size = raceBodyBytes
		}
		n := size / 4 * 3
		// Repeated '}' encodes to fX19: no form-query '+' and neither base32
		// alphabet. This isolates the base64 layer from unrelated
		// decode branches and malformed-UTF-8 normalization.
		plain := bytes.Repeat([]byte{'}'}, n)
		return base64.StdEncoding.EncodeToString(plain), "text/plain"
	default:
		panic("unknown decode workload")
	}
}

func TestDecodeBudgetLargeForwardJSONBody(t *testing.T) {
	t.Parallel()
	testDecodeBudgetLargeForwardBody(t, "json")
}

func TestDecodeBudgetLargeForwardHexBody(t *testing.T) {
	t.Parallel()
	testDecodeBudgetLargeForwardBody(t, "hex")
}

func TestDecodeBudgetLargeForwardBase64Body(t *testing.T) {
	t.Parallel()
	testDecodeBudgetLargeForwardBody(t, "base64")
}

func testDecodeBudgetLargeForwardBody(t *testing.T, name string) {
	t.Helper()
	body, contentType := decodeBudgetBody(name)
	want := sha256.Sum256([]byte(body))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil || sha256.Sum256(got) != want {
			t.Error("upload bytes changed")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	addr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.DLP.ScanEnv = false
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.MaxBodyBytes = 16 * 1024 * 1024
	})
	defer cleanup()
	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL+"/upload", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("%d-byte body: status %d", len(body), resp.StatusCode)
	}
	t.Logf("delivered %d bytes", len(body))
}

// A large body that carries a credential must still be scanned and refused, so
// the delivery tests above can't pass against a proxy that skips scanning at
// these sizes. The body matches the largest delivery case (the 9 MiB base64
// body) under the same 16 MiB scan cap; under the race detector it uses the
// same modest size as the other cases. The hex and base64 variants encode the
// whole body, so the credential is only visible after the large first layer is
// decoded. They use the 3 MiB hex delivery size: rescanning megabytes of
// decoded prose is far slower than the delivery workloads, and the scanner's
// decode-budget tests own the size boundaries.
func TestDecodeBudgetLargeForwardBodyBlocksCredential(t *testing.T) {
	t.Parallel()
	testDecodeBudgetLargeForwardBodyBlocksCredential(t, "plain")
}

func TestDecodeBudgetLargeForwardHexBodyBlocksCredential(t *testing.T) {
	t.Parallel()
	testDecodeBudgetLargeForwardBodyBlocksCredential(t, "hex")
}

func TestDecodeBudgetLargeForwardBase64BodyBlocksCredential(t *testing.T) {
	t.Parallel()
	testDecodeBudgetLargeForwardBodyBlocksCredential(t, "base64")
}

func testDecodeBudgetLargeForwardBodyBlocksCredential(t *testing.T, encoding string) {
	t.Helper()
	const scanCap = 16 * 1024 * 1024
	size := 9 * 1024 * 1024
	if encoding != "plain" {
		size = 3 * 1024 * 1024
	}
	if raceEnabled {
		size = 128 * 1024
	}
	// Built at runtime so no credential literal sits in source.
	marker := "AKIA" + strings.Repeat("B", 16)
	encodedBody := func(size int, marker string) string {
		// Plain bytes that encode to about size bytes.
		plainSize := size
		switch encoding {
		case "hex":
			plainSize = size / 2
		case "base64":
			plainSize = size / 4 * 3
		}
		// Ordinary space-separated words, like a prose upload.
		body := strings.Repeat("upload body text ", (plainSize-len(marker))/17) + marker
		switch encoding {
		case "hex":
			return hex.EncodeToString([]byte(body))
		case "base64":
			return base64.StdEncoding.EncodeToString([]byte(body))
		}
		return body
	}
	body := encodedBody(size, marker)
	if encoding != "plain" && strings.Contains(body, "AKIA") {
		t.Fatal("encoded body still carries the plain credential")
	}
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	addr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.DLP.ScanEnv = false
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.MaxBodyBytes = scanCap
	})
	defer cleanup()
	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	post := func(body string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL+"/upload", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "text/plain")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, resp.Header.Get("X-Pipelock-Block-Reason")
	}
	// Control: the same encoding and filler without the credential is
	// delivered, so the refusal below comes from the credential. The control
	// uses the race size in every build; its size doesn't change what it shows.
	if status, reason := post(encodedBody(128*1024, strings.Repeat("B", len(marker)))); status != http.StatusNoContent || upstreamHits.Load() != 1 {
		t.Fatalf("%s control without a credential: status %d reason %q upstream hits %d, want 204 and 1", encoding, status, reason, upstreamHits.Load())
	}
	status, reason := post(body)
	if status != http.StatusForbidden {
		t.Fatalf("%d-byte body with a credential: status %d, want 403", len(body), status)
	}
	if reason != "dlp_match" {
		t.Fatalf("refusal reason %q, want dlp_match", reason)
	}
	t.Logf("refused %d-byte %s body: %s", len(body), encoding, reason)
	if upstreamHits.Load() != 1 {
		t.Fatal("refused body reached the upstream")
	}
}

func TestDecodeBudgetLargeWebSocketJSONFrame(t *testing.T) {
	t.Parallel()
	testDecodeBudgetLargeWebSocketFrame(t, "json")
}

func TestDecodeBudgetLargeWebSocketHexFrame(t *testing.T) {
	t.Parallel()
	testDecodeBudgetLargeWebSocketFrame(t, "hex")
}

func TestDecodeBudgetLargeWebSocketBase64Frame(t *testing.T) {
	t.Parallel()
	testDecodeBudgetLargeWebSocketFrame(t, "base64")
}

func testDecodeBudgetLargeWebSocketFrame(t *testing.T, name string) {
	t.Helper()
	body, _ := decodeBudgetBody(name)
	backend, closeBackend := wsDigestServer(t)
	defer closeBackend()
	wsDefaults := config.Defaults().WebSocketProxy
	addr, cleanup := setupWSProxy(t, func(cfg *config.Config) {
		cfg.DLP.ScanEnv = false
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.MaxBodyBytes = 16 * 1024 * 1024
		cfg.WebSocketProxy.MaxMessageBytes = 16 * 1024 * 1024
		// Race-instrumented multi-megabyte scans can exceed the shipped
		// idle timer. Let the enclosing test deadline bound that wait.
		cfg.WebSocketProxy.MaxConnectionSeconds = wsDefaults.MaxConnectionSeconds
		cfg.WebSocketProxy.IdleTimeoutSeconds = wsDefaults.IdleTimeoutSeconds
		if deadline, ok := t.Deadline(); ok {
			cfg.WebSocketProxy.IdleTimeoutSeconds = max(cfg.WebSocketProxy.IdleTimeoutSeconds,
				int(time.Until(deadline)/time.Second)+1)
		}
	})
	defer cleanup()
	conn := dialWS(t, addr, backend)
	defer func() { _ = conn.Close() }()
	if deadline, ok := t.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}
	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(body)); err != nil {
		t.Fatal(err)
	}
	reply, op, err := wsutil.ReadServerData(conn)
	want := sha256.Sum256([]byte(body))
	if err != nil || op != ws.OpText || string(reply) != hex.EncodeToString(want[:]) {
		t.Fatalf("%d-byte client frame: opcode=%v digest=%q error=%v", len(body), op, reply, err)
	}
	t.Logf("allowed %d-byte client frame", len(body))
}

// wsDigestServer reads one client message and replies with the hex SHA-256 of
// the bytes it received, so a proxy that alters a frame can't pass as allowing
// it. A failed read sends no reply.
func wsDigestServer(t *testing.T) (string, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, upgradeErr := ws.UpgradeHTTP(r, w)
		if upgradeErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		msg, op, readErr := wsutil.ReadClientData(conn)
		if readErr != nil || op != ws.OpText {
			return
		}
		sum := sha256.Sum256(msg)
		_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte(hex.EncodeToString(sum[:])))
	}))
	return srv.Listener.Addr().String(), srv.Close
}
