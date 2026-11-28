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
	"strconv"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidence/receiptinput"
	"github.com/luckyPipewrench/pipelock/internal/evidencename"
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

func TestDashboardRebuildGuardChecksEveryFileInLargeDirectory(t *testing.T) {
	const command = "dashboard"
	dir := t.TempDir()
	for i := 0; i <= maxEvidenceVerificationFiles; i++ {
		if err := os.WriteFile(filepath.Join(dir, "evidence-s"+strconv.Itoa(i)+"-0.jsonl"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A large legacy directory stays usable.
	if err := refuseReadModelSources(dir, command); err != nil {
		t.Fatalf("large legacy directory refused: %v", err)
	}
	// A receipt-profile file past the bounded listing is still refused.
	profile := "  " + evidencename.ReceiptProfilePrefix + "\n"
	if err := os.WriteFile(filepath.Join(dir, "evidence-v3.jsonl"), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refuseReadModelSources(dir, command); !errors.Is(err, receiptinput.ErrUnsupported) {
		t.Fatalf("large directory with receipt-profile evidence = %v, want unsupported", err)
	}
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

func TestDashboardAgentsHandlersAndSingleDashEvidenceRefuseReceiptV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, _ string) {
		m := NewReadModel(Options{ReceiptDir: dir})
		handler := &dashboardHandler{model: m}
		for _, route := range []struct {
			path string
			fn   func(http.ResponseWriter, *http.Request)
		}{
			{"/agents", handler.handleAgents},
			{"/agent/example", handler.handleAgent},
		} {
			resp := httptest.NewRecorder()
			route.fn(resp, httptest.NewRequestWithContext(t.Context(), http.MethodGet, route.path, nil))
			if resp.Code != http.StatusConflict {
				t.Fatalf("%s HTTP status: %d, want %d; body=%q", route.path, resp.Code, http.StatusConflict, resp.Body.String())
			}
			testreceipt.RequiresV3Refusal(t, errors.New(resp.Body.String()), "dashboard", "the dashboard")
		}
	})

	// Single-dash evidence-v3.jsonl is matched by filterEvidenceEntries but skipped
	// by v3 directory legacyCandidate; rebuild and index inspection must still refuse it.
	v3File, _ := testreceipt.V3(t, t.TempDir(), false)
	v3Data, err := os.ReadFile(filepath.Clean(v3File))
	if err != nil {
		t.Fatal(err)
	}
	singleDashDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(singleDashDir, "evidence-v3.jsonl"), v3Data, 0o600); err != nil {
		t.Fatal(err)
	}
	indexOut := filepath.Join(t.TempDir(), "index.json")
	testreceipt.RequiresV3Refusal(t, RebuildReadModel(RebuildOptions{SourceDir: singleDashDir, Output: indexOut}), "dashboard rebuild", "the dashboard read model")
	if _, statErr := os.Stat(indexOut); !os.IsNotExist(statErr) {
		t.Fatalf("refused rebuild created index: %v", statErr)
	}
	_, _, inspectErr := InspectReadModelIndex(indexOut, singleDashDir)
	testreceipt.RequiresV3Refusal(t, inspectErr, "dashboard", "the dashboard read model")
}

func TestDashboardRefusesRenamedV3InMultiLocationSubdir(t *testing.T) {
	v3File, _ := testreceipt.V3(t, t.TempDir(), false)
	v3Data, err := os.ReadFile(filepath.Clean(v3File))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "evidence-proxy-0.jsonl"), []byte("{\"v\":1,\"seq\":0}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "evidence-proxy-0.jsonl"), append([]byte("\n  "), v3Data...), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewReadModel(Options{ReceiptDir: root})
	_, sessionsErr := m.Sessions()
	_, sessionErr := m.Session("proxy")
	_, trustErr := m.TrustKeys()
	for _, err := range []error{sessionsErr, sessionErr, trustErr} {
		testreceipt.RequiresV3Refusal(t, err, "dashboard", "the dashboard")
	}
	handler := &dashboardHandler{model: m}
	resp := httptest.NewRecorder()
	handler.handleIndex(resp, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/evidence", nil))
	if resp.Code != http.StatusConflict {
		t.Fatalf("HTTP status: %d, want %d; body=%q", resp.Code, http.StatusConflict, resp.Body.String())
	}
	testreceipt.RequiresV3Refusal(t, errors.New(resp.Body.String()), "dashboard", "the dashboard")
}
