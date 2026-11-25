// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardBarePolicyDecisions(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, action := range []string{config.ActionBlock, config.ActionWarn} {
		h := newTestHandler(t)
		h.scanner.Close()
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.CardBareAction = action
		h.scanner = scanner.MustNew(cfg)
		t.Cleanup(h.scanner.Close)
		for _, tc := range []struct {
			text string
			want string
		}{
			{pan, map[string]string{config.ActionBlock: DecisionDeny, config.ActionWarn: DecisionWarn}[action]},
			{"visa " + pan[:4] + "." + pan[4:], DecisionDeny},
			{pan + "e0", DecisionDeny},
			{"F27=" + pan[:4] + "." + pan[4:], DecisionAllow},
		} {
			body, err := json.Marshal(map[string]any{"kind": KindDLP, "input": map[string]string{"text": tc.text}})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			var result Response
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK || result.Decision != tc.want {
				t.Fatalf("%s %q: %+v", action, tc.text, result)
			}
		}
	}
}
