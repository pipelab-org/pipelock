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

// TestAuditModeMCPInputFloors records input floors that stay refused for
// both enforce values. EvaluateMCPInputGates keeps the core credential
// floor, the hostname-exfiltration floor, and an unfinished inspection
// when input scanning is off. The MCP proxy does not read enforce, and
// the scanner does not store it, so the two settings match.
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
				for _, enforce := range []bool{false, true} {
					cfg := config.Defaults()
					cfg.Internal = nil
					cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
					cfg.ResponseScanning.Action = config.ActionWarn
					cfg.Enforce = &enforce
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					opts := testOpts(sc)
					opts.InputCfg = &InputScanConfig{Enabled: enabled, Action: config.ActionWarn, OnParseError: config.ActionBlock}
					if got := scanHTTPInputDecision(msg, io.Discard, "session", "session", opts); got.Blocked == nil {
						t.Errorf("HTTP enabled=%v enforce=%v released the floor", enabled, enforce)
					}
					var out bytes.Buffer
					blocked := make(chan BlockedRequest, 2)
					ForwardScannedInput(transport.NewStdioReader(bytes.NewReader(append(append([]byte(nil), msg...), '\n'))), transport.NewStdioWriter(&out), io.Discard, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
					if out.Len() != 0 || len(blocked) == 0 {
						t.Errorf("stdio enabled=%v enforce=%v forwarded=%d blocked=%d", enabled, enforce, out.Len(), len(blocked))
					}
				}
			}
		})
	}
}

// TestAuditModeMCPRequiredReceipt records the receipt gate. RequireReceipts
// lives on MCPProxyOpts. A missing emitter refuses an ordinary tool call and
// a healthy emitter allows it. Config.Enforce is not read, so both settings
// produce that pair.
func TestAuditModeMCPRequiredReceipt(t *testing.T) {
	msg := []byte(makeRequest(1, "tools/call", map[string]any{"name": "send", "arguments": map[string]string{"text": "ordinary"}}))
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce=%t", enforce), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			cfg.Enforce = &enforce
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			opts := testOpts(sc)
			opts.RequireReceipts = true
			opts.Transport = transportMCPStdio
			opts.PolicyHash = mcpTestPolicyHash
			if got := scanHTTPInputDecision(msg, io.Discard, "session", "session", opts); got.Blocked == nil {
				t.Fatal("released without required receipt")
			}
			emitter, _, _, _ := newReceiptTestHarness(t)
			opts.ReceiptEmitter = emitter
			if got := scanHTTPInputDecision(msg, io.Discard, "session", "session", opts); got.Blocked != nil {
				t.Fatalf("refused healthy receipt: %+v", got.Blocked)
			}
		})
	}
}

// TestAuditModeMCPListenerProtocolAdmission records listener admission.
// An unsupported method, a malformed session id, and a malformed listener
// token are refused in the listener before a scan. Those checks do not read
// enforce, so both settings return the same status and do not reach the
// upstream.
func TestAuditModeMCPListenerProtocolAdmission(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("invalid listener request reached upstream")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce=%t", enforce), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			cfg.Enforce = &enforce
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			opts := testOpts(sc)
			base, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			runAuditModeMCPListenerAdmission(t, base)
		})
	}
}

func runAuditModeMCPListenerAdmission(t *testing.T, base string) {
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

// TestAuditModeMCPFragmentInspection records a reassembled number past the
// fixed JSON exponent bound. The fragment scanner blocks that inspection
// limit even when the cross-request action is warn. Config.Enforce is not
// read on this path, and the scanner does not store it, so both settings
// refuse the second message and release the first.
func TestAuditModeMCPFragmentInspection(t *testing.T) {
	first := makeRequest(86, methodToolsCall, map[string]any{"name": "echo", "arguments": map[string]string{"payload": `{"n":1e`}})
	second := makeRequest(87, methodToolsCall, map[string]any{"name": "echo", "arguments": map[string]string{"payload": `10001}`}})
	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce=%t", enforce), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			cfg.Enforce = &enforce
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			opts := MCPProxyOpts{Scanner: sc, CEE: newCEERuntimeMatrixDeps(t)}
			opts.CEE.Reconfigure(config.CrossRequestDetection{Enabled: true, Action: config.ActionWarn, FragmentReassembly: config.CrossRequestFragments{Enabled: true, MaxBufferBytes: 4096, WindowMinutes: 5}}, nil)
			if result := scanHTTPInputDecision([]byte(first), io.Discard, "limit-session", "audit", opts); result.Blocked != nil {
				t.Fatalf("seed refused: %+v", result.Blocked)
			}
			if result := scanHTTPInputDecision([]byte(second), io.Discard, "limit-session", "audit", opts); result.Blocked == nil {
				t.Fatal("fragment inspection limit released")
			}
		})
	}
}
