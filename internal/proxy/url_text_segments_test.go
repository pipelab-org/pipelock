// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestForwardURLTextSegments(t *testing.T) {
	secret := "synthetic-" + "credential-value-42"
	path := filepath.Join(t.TempDir(), "values")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ordinary")
	}))
	t.Cleanup(origin.Close)
	cfg := config.Defaults()
	cfg.Internal = nil // Allow the local test origin, without external DNS.
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.SecretsFile = path
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = nil
	cfg.Enforce = new(true)
	cfg.ForwardProxy.Enabled = true
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
	sc := scanner.MustNew(cfg)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", auditPath, true, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	encode := func(s string) string { return hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(s)))) }

	for _, field := range []string{"target", "header", "body", "fetch"} {
		t.Run(field, func(t *testing.T) {
			for _, tc := range []struct {
				name, value string
				status      int
				calls       int32
			}{
				{"ordinary", "ordinary", http.StatusOK, 1},
				{"encoded ordinary", encode("note:ordinary"), http.StatusOK, 1},
				{"configured", encode("note:" + secret), http.StatusForbidden, 0},
			} {
				t.Run(tc.name, func(t *testing.T) {
					value := origin.URL + "/receive#" + tc.value
					target, body := origin.URL+"/receive", `{"note":"ordinary"}`
					if field == "target" {
						target = value
					}
					if field == "body" {
						body = `{"note":"` + value + `"}`
					}
					r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(body))
					r.RemoteAddr = "192.0.2.1:12345"
					r.Header.Set("Content-Type", "application/json")
					if field == "header" {
						r.Header.Set("X-Note", value)
					}
					calls.Store(0)
					w := httptest.NewRecorder()
					if field == "fetch" {
						r = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(value), nil)
						p.handleFetch(w, r)
					} else {
						p.handleForwardHTTP(w, r)
					}
					if w.Code != tc.status || calls.Load() != tc.calls {
						t.Errorf("status=%d calls=%d, want status=%d calls=%d", w.Code, calls.Load(), tc.status, tc.calls)
					}
					if field == "target" {
						safe := receipt.SanitizeTarget(r.URL.String(), func(s string) bool { return sc.ScanTextForDLP(t.Context(), s).Clean })
						if tc.calls == 0 && strings.Contains(safe, tc.value) {
							t.Error("receipt target retained the configured value")
						}
						if tc.calls == 1 && safe != r.URL.String() {
							t.Error("receipt target changed an ordinary value")
						}
					}
				})
			}
		})
	}
	logBytes, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	allowed := 0
	fetchAllowed := 0
	for _, line := range strings.Split(strings.TrimSpace(string(logBytes)), "\n") {
		var event struct {
			Event string `json:"event"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.Event == string(audit.EventForwardHTTP) {
			allowed++
		}
		if event.Event == string(audit.EventAllowed) {
			fetchAllowed++
		}
	}
	if allowed != 6 {
		t.Errorf("allowed audit records=%d, want 6", allowed)
	}
	if fetchAllowed != 2 {
		t.Errorf("allowed fetch audit records=%d, want 2", fetchAllowed)
	}
	encoded := encode("note:" + secret)
	if strings.Contains(string(logBytes), encoded) {
		t.Error("audit log retained the configured value")
	}
}

func TestForwardURLTextSegmentsPattern(t *testing.T) {
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)
	cfg := config.Defaults()
	cfg.Internal = nil // Allow the local test origin, without external DNS.
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "synthetic value", Regex: "SYNTHETIC_VALUE_[0-9]+", Severity: config.SeverityCritical}}
	cfg.Enforce = new(true)
	cfg.ForwardProxy.Enabled = true
	p := newTestProxyWithConfig(t, cfg)
	for _, tc := range []struct {
		name, value string
		status      int
		calls       int32
	}{
		{"ordinary", "note:ordinary", http.StatusOK, 1},
		{"pattern", "note:SYNTHETIC_VALUE_42", http.StatusForbidden, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, origin.URL+"/receive#"+hex.EncodeToString([]byte(tc.value)), nil)
			r.RemoteAddr = "192.0.2.1:12345"
			calls.Store(0)
			w := httptest.NewRecorder()
			p.handleForwardHTTP(w, r)
			if w.Code != tc.status || calls.Load() != tc.calls {
				t.Errorf("status=%d calls=%d, want status=%d calls=%d", w.Code, calls.Load(), tc.status, tc.calls)
			}
		})
	}
}
