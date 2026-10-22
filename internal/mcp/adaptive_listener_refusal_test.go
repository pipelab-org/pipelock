// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// The listener's clean-only error relay is an independent refusal policy.
// Its findings score even when ordinary tool-result scanning is configured
// to warn. A response action alone cannot classify the final decision.
func TestAdaptiveListenerWarningAndIndependentRefusal(t *testing.T) {
	for _, action := range []string{config.ActionWarn, config.ActionBlock} {
		t.Run(action, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				var request struct {
					ID     json.RawMessage `json:"id"`
					Method string          `json:"method"`
					Params struct {
						Name string `json:"name"`
					} `json:"params"`
				}
				if err := json.Unmarshal(body, &request); err != nil {
					t.Errorf("decode upstream request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch {
				case request.Method == "initialize":
					_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"test","version":"1"}}}`, request.ID)
				case request.Params.Name == "refusal":
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = io.WriteString(w, upstreamStatusInjection)
				case request.Params.Name == "benign_refusal":
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = io.WriteString(w, "invalid argument")
				default:
					_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":%q}]}}`, request.ID, upstreamStatusInjection)
				}
			}))
			t.Cleanup(upstream.Close)
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.ResponseScanning.Action = action
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			rec := &mockRecorder{}
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
				Scanner: sc, Store: &airlockRecorderStore{rec: rec},
				AdaptiveCfg: adaptiveCfgEnabled(), listenerStateTokenRequired: boolPtr(true),
			})
			token := listenerSetupToken(t, baseURL)
			header := http.Header{listenerSessionTokenHeader: {token}}
			request := func(name string, id int) (listenerReply, []byte) {
				return doListenerRequest(t, http.MethodPost, baseURL+"/", fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, id, name), header)
			}
			before := rec.ThreatScore()
			for i := range 25 {
				_, body := request("result", i+1)
				delivered := strings.Contains(string(body), upstreamStatusInjection)
				if delivered != (action == config.ActionWarn) {
					t.Fatalf("action=%s delivered=%t reply=%s", action, delivered, body)
				}
			}
			if action == config.ActionWarn && rec.ThreatScore() != before {
				t.Fatalf("warning burst scored: %v", rec.signals)
			}
			if action == config.ActionBlock && rec.ThreatScore() <= before {
				t.Fatal("explicit response refusals did not score")
			}
			before = rec.ThreatScore()
			resp, body := request("benign_refusal", 30)
			if resp.StatusCode != http.StatusBadRequest || string(body) != "invalid argument" || rec.ThreatScore() != before {
				t.Fatalf("benign refusal: status=%d body=%s score=%v want=%v", resp.StatusCode, body, rec.ThreatScore(), before)
			}
			resp, body = request("refusal", 31)
			if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), upstreamStatusInjection) {
				t.Fatalf("independent refusal: status=%d body=%s", resp.StatusCode, body)
			}
			if got, want := rec.ThreatScore(), before+session.SignalPoints[session.SignalBlock]; got != want {
				t.Fatalf("independent refusal score=%v want=%v", got, want)
			}
			t.Logf("action=%s: tool-result policy preserved; benign 4xx relayed; withheld finding added %v points", action, session.SignalPoints[session.SignalBlock])
		})
	}
}
