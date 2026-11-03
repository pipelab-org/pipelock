// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	backend, closeBackend := wsAckServer(t)
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
	if err != nil || op != ws.OpText || string(reply) != "ok" {
		t.Fatalf("%d-byte client frame: opcode=%v acknowledgement=%q error=%v", len(body), op, reply, err)
	}
	t.Logf("allowed %d-byte client frame", len(body))
}
