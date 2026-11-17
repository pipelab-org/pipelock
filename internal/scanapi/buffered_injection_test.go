// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBufferedCheckerScanAPI(t *testing.T) {
	for _, kind := range []string{"prompt_injection", "tool_call"} {
		for _, state := range []string{"benign", "finding", "failure", "not_checked"} {
			for _, mode := range []string{config.InjectionModeOff, config.InjectionModeWarn, config.InjectionModeBlock} {
				t.Run(kind+"/"+state+"/"+mode, func(t *testing.T) {
					srv := checkertest.New(t, state)
					cfg := config.Defaults()
					cfg.Internal = nil
					cfg.DLP.ScanEnv = false
					cfg.ScanAPI.Auth.BearerTokens = []string{testToken}
					srv.Configure(cfg, config.InjectionSurfaceScanAPI, mode)
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					text := "ordinary API content"
					if state == "benign" {
						text = checkertest.Directive
					}
					body := `{"kind":"prompt_injection","input":{"content":"` + text + `"}}`
					if kind == "tool_call" {
						body = `{"kind":"tool_call","input":{"tool_name":"notes","arguments":{"text":"` + text + `"}}}`
					}
					h := NewHandler(cfg, sc, nil, metrics.New(), "test-version")
					req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Authorization", "Bearer "+testToken)
					w := httptest.NewRecorder()
					h.ServeHTTP(w, req)
					block := mode == config.InjectionModeBlock && state != "benign"
					if block && state != "finding" {
						if w.Code != http.StatusInternalServerError {
							t.Fatalf("status=%d: %s", w.Code, w.Body.String())
						}
						return
					}
					if w.Code != http.StatusOK {
						t.Fatalf("status=%d: %s", w.Code, w.Body.String())
					}
					var resp Response
					if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
						t.Fatal(err)
					}
					want := DecisionAllow
					if block {
						want = DecisionDeny
					} else if mode == config.InjectionModeWarn && state == "finding" {
						want = DecisionWarn
					}
					if resp.Decision != want {
						t.Fatalf("decision=%s want %s: %s", resp.Decision, want, w.Body.String())
					}
					if mode != config.InjectionModeOff && len(srv.Items()) != 1 {
						t.Fatalf("calls=%d", len(srv.Items()))
					}
				})
			}
		}
	}
}
