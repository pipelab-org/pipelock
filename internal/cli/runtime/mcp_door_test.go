// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func runtimeDoorConfig(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "pinned"}}})
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(keyPath, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf("mcp_door:\n  enabled: true\n  issuer: https://issuer.example\n  audience: https://resource.example/mcp\n  mode: jwt\n  jwks_file: %q\n  enrollments:\n    - subject: caller\n      client_id: cloud\n", keyPath)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "pinned"}}, (&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{"iss": "https://issuer.example", "aud": "https://resource.example/mcp", "sub": "caller", "client_id": "cloud", "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(), "jti": "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw, token
}

func writeDoorConfig(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "door.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMCPDoorStartupRefusals(t *testing.T) {
	raw, _ := runtimeDoorConfig(t)
	tokenFile := filepath.Join(t.TempDir(), "static")
	if err := os.WriteFile(tokenFile, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()
	for _, tc := range []struct {
		name, raw string
		flags     []string
		want      string
	}{
		{"issuer", strings.Replace(raw, "  issuer: https://issuer.example\n", "", 1), nil, "issuer"},
		{"audience", strings.Replace(raw, "  audience: https://resource.example/mcp\n", "", 1), nil, "audience"},
		{"missing keys", strings.Replace(raw, "  jwks_file:", "  unused_file:", 1), nil, "field unused_file"},
		{"unavailable keys", fmt.Sprintf("mcp_door:\n  enabled: true\n  issuer: https://issuer.example\n  audience: https://resource.example/mcp\n  mode: jwt\n  jwks_file: %q\n", filepath.Join(t.TempDir(), "missing.json")), nil, "verifier material unavailable"},
		{"anonymous fallback", raw, []string{"--listener-allow-unauthenticated"}, "cannot be combined"},
		{"static fallback", raw, []string{"--listener-auth-token-file", tokenFile}, "cannot be combined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := McpCmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetIn(strings.NewReader(""))
			args := []string{"proxy", "--listen", "0.0.0.0:0", "--upstream", upstream.URL, "--config", writeDoorConfig(t, tc.raw)}
			cmd.SetArgs(append(args, tc.flags...))
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("startup %v, want %q", err, tc.want)
			}
			if calls.Load() != 0 {
				t.Fatal("startup refusal contacted upstream")
			}
		})
	}
	path := writeDoorConfig(t, raw)
	cmd := McpCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"proxy", "--upstream", upstream.URL, "--config", path})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "requires mcp proxy --listen") {
		t.Fatalf("non-listener silently ignored door: %v", err)
	}
	if _, err := NewServer(ServerOpts{ConfigFile: path}); err == nil || !strings.Contains(err.Error(), "run does not support door mode") {
		t.Fatalf("run silently ignored door: %v", err)
	}
}

func TestMCPDoorCommandNonLoopback(t *testing.T) {
	raw, token := runtimeDoorConfig(t)
	path := writeDoorConfig(t, raw)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("door token forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	}))
	defer upstream.Close()
	testport.WithRetry(t, 1, func(addrs []string) (runErr error) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cmd := McpCmd()
		cmd.SetContext(ctx)
		cmd.SetOut(io.Discard)
		var stderr syncBuffer
		cmd.SetErr(&stderr)
		cmd.SetArgs([]string{"proxy", "--listen", strings.Replace(addrs[0], "127.0.0.1", "0.0.0.0", 1), "--upstream", upstream.URL, "--config", path})
		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()
		exited := false
		defer func() {
			cancel()
			if exited {
				return
			}
			select {
			case err := <-done:
				if runErr == nil && err != nil && !errors.Is(err, context.Canceled) {
					runErr = fmt.Errorf("door command stop: %w", err)
				}
			case <-time.After(testwait.Deadline(10 * time.Second)):
				if runErr == nil {
					runErr = errors.New("door command did not stop")
				}
			}
		}()
		base := "http://" + addrs[0]
		ready := func() bool {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
			if err != nil {
				return false
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return false
			}
			_ = resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		}
		// A bind collision makes the command exit before it is ready; return that
		// error so WithRetry can try another port instead of waiting out the deadline.
		deadline := time.After(testwait.Deadline(10 * time.Second))
		for !ready() {
			select {
			case err := <-done:
				exited = true
				return fmt.Errorf("door command exited before ready: %w; stderr %s", err, stderr.String())
			case <-deadline:
				return fmt.Errorf("door command listener not ready; stderr %s", stderr.String())
			case <-time.After(20 * time.Millisecond):
			}
		}
		for _, auth := range []string{"", token} {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
			req.Header.Set("Mcp-Method", "tools/list")
			if auth != "" {
				req.Header.Set("Authorization", "Bearer "+auth)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			want := 200
			if auth == "" {
				want = 401
			}
			if resp.StatusCode != want {
				t.Fatalf("door command: %d want %d: %s; stderr %s", resp.StatusCode, want, body, stderr.String())
			}
		}
		if calls.Load() != 1 {
			t.Fatalf("backend calls %d want 1", calls.Load())
		}
		return nil
	})
}
