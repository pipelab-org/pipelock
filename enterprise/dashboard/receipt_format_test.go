//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		handler.handleIndex(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/evidence", nil))
		if response.Code != http.StatusConflict {
			t.Fatalf("HTTP status: %d", response.Code)
		}
		testreceipt.RequiresV3Refusal(t, errors.New(response.Body.String()), "dashboard", "the dashboard")
		for _, err := range []error{sessionsErr, sessionErr, actionErr, trustErr} {
			testreceipt.RequiresV3Refusal(t, err, "dashboard", "the dashboard")
		}
		_, _, indexErr := InspectReadModelIndex("", dir)
		testreceipt.RequiresV3Refusal(t, indexErr, "dashboard", "the dashboard read model")
		testreceipt.RequiresV3Refusal(t, RebuildReadModel(RebuildOptions{SourceDir: dir}), "dashboard rebuild", "the dashboard read model")
	})
}

func TestDashboardRefusesReceiptV3InResolvedSubdir(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "location-a")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	testreceipt.V3(t, sub, false)
	if err := os.WriteFile(filepath.Join(sub, "evidence-proxy-0.jsonl"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewReadModel(Options{ReceiptDir: root})
	_, sessionsErr := m.Sessions()
	_, sessionErr := m.Session("proxy")
	_, _, actionErr := m.ReceiptActionDetail("proxy", "action")
	_, trustErr := m.TrustKeys()
	for _, err := range []error{sessionsErr, sessionErr, actionErr, trustErr} {
		testreceipt.RequiresV3Refusal(t, err, "dashboard", "the dashboard")
	}
}
