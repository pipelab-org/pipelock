//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestDashboardRefusesReceiptV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, _ string) {
		m := NewReadModel(Options{ReceiptDir: dir})
		_, sessionsErr := m.Sessions()
		_, sessionErr := m.Session("proxy")
		_, _, actionErr := m.ReceiptActionDetail("proxy", "action")
		_, trustErr := m.TrustKeys()
		handler := &dashboardHandler{model: m}
		response := httptest.NewRecorder()
		handler.handleIndex(response, httptest.NewRequest(http.MethodGet, "/evidence", nil))
		if response.Code != http.StatusConflict {
			t.Fatalf("HTTP status: %d", response.Code)
		}
		testreceipt.RequiresV3Refusal(t, errors.New(response.Body.String()), "dashboard", "the dashboard")
		for _, err := range []error{sessionsErr, sessionErr, actionErr, trustErr} {
			testreceipt.RequiresV3Refusal(t, err, "dashboard", "the dashboard")
		}
		testreceipt.RequiresV3Refusal(t, RebuildReadModel(RebuildOptions{SourceDir: dir}), "dashboard rebuild", "the dashboard read model")
	})
}
