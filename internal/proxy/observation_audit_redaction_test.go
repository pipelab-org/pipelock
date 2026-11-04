// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestObservationAuditURLRedaction(t *testing.T) {
	for _, mode := range []string{"enforce_false", "audit_preset"} {
		for _, transport := range []string{"fetch", "forward"} {
			for _, carrier := range []string{"path", "query", "userinfo"} {
				t.Run(mode+"/"+transport+"/"+carrier, func(t *testing.T) {
					secret := strings.Join([]string{"synthetic", "credential", "observation42"}, "-")
					var calls atomic.Int32
					origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						_, _ = io.WriteString(w, "ordinary response")
					}))
					t.Cleanup(origin.Close)
					cfg := config.Defaults()
					if mode == "audit_preset" {
						var err error
						cfg, err = config.Load(filepath.Join("..", "..", "configs", "audit.yaml"))
						if err != nil {
							t.Fatal(err)
						}
					}
					cfg.Enforce = new(false)
					cfg.Internal = nil
					cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
					cfg.APIAllowlist = nil
					cfg.AdaptiveEnforcement.Enabled = false
					cfg.DLP.ScanEnv = false
					cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
						Name: "Synthetic observation credential", Regex: regexp.QuoteMeta(secret), Severity: config.SeverityHigh,
					})
					cfg.ForwardProxy.Enabled = true
					logPath := filepath.Join(t.TempDir(), "audit.jsonl")
					logger, err := audit.New("json", "file", logPath, true, true)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(logger.Close)
					p, err := New(cfg, logger, scanner.MustNew(cfg), metrics.New())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(p.Close)
					target, err := url.Parse(origin.URL + "/ordinary")
					if err != nil {
						t.Fatal(err)
					}
					switch carrier {
					case "path":
						target.Path = "/" + secret
					case "query":
						target.RawQuery = "credential=" + secret
					case "userinfo":
						target.User = url.UserPassword("user", secret)
					}
					requestURL := target.String()
					if transport == "fetch" {
						requestURL = "/fetch?url=" + url.QueryEscape(requestURL)
					}
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil)
					w := httptest.NewRecorder()
					if transport == "fetch" {
						p.handleFetch(w, req)
					} else {
						p.handleForwardHTTP(w, req)
					}
					if w.Code != http.StatusOK || calls.Load() != 1 {
						t.Fatalf("status=%d calls=%d, want 200 and one upstream request", w.Code, calls.Load())
					}
					// A failed dispatch must not echo the same URL through
					// the HTTP client's structured error, either.
					origin.Close()
					failed := httptest.NewRecorder()
					failedReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil)
					if transport == "fetch" {
						p.handleFetch(failed, failedReq)
					} else {
						p.handleForwardHTTP(failed, failedReq)
					}
					if failed.Code != http.StatusBadGateway {
						t.Fatalf("failed dispatch status=%d, want 502", failed.Code)
					}
					logger.Close()
					raw, err := os.ReadFile(filepath.Clean(logPath))
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(raw), secret) {
						t.Error("raw credential reached audit log")
					}
					allowedEvent := string(audit.EventAllowed)
					if transport == "forward" {
						allowedEvent = string(audit.EventForwardHTTP)
					}
					allowed, warned, failedEvent := false, false, false
					for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
						var entry struct {
							Event   string `json:"event"`
							URL     string `json:"url"`
							Status  int    `json:"status_code"`
							Scanner string `json:"scanner"`
						}
						if err := json.Unmarshal([]byte(line), &entry); err != nil {
							t.Fatal(err)
						}
						if entry.Event == string(audit.EventError) {
							failedEvent = true
						}
						if entry.Event == allowedEvent {
							allowed = true
							if entry.URL != origin.URL || entry.Status != http.StatusOK {
								t.Errorf("allowed destination=%q status=%d, want %q and 200", entry.URL, entry.Status, origin.URL)
							}
						}
						if entry.Event == string(audit.EventAnomaly) && entry.Scanner == scanner.ScannerDLP {
							warned = true
							if !strings.Contains(entry.URL, target.Host) {
								t.Error("warning lost destination")
							}
						}
					}
					if !allowed || !warned || !failedEvent {
						t.Errorf("allowed=%t DLP warning=%t error=%t, want all", allowed, warned, failedEvent)
					}
				})
			}
		}
	}
}
