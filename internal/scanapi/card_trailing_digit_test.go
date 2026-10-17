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
)

func TestTrailingDigitCardScanAPI(t *testing.T) {
	h := newTestHandler(t)
	t.Cleanup(h.scanner.Close)
	for _, tt := range cardtest.TrailingDigitCases() {
		text, err := json.Marshal(tt.Text)
		if err != nil {
			t.Fatal(err)
		}
		for _, body := range []string{
			`{"kind":"dlp","input":{"text":` + string(text) + `}}`,
			`{"kind":"tool_call","input":{"tool_name":"report","arguments":{"note":` + string(text) + `}}}`,
		} {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			var result Response
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK || (result.Decision == DecisionDeny) == tt.Clean {
				t.Fatalf("%s: status=%d decision=%s want clean=%v", tt.Name, w.Code, result.Decision, tt.Clean)
			}
		}
	}
}
