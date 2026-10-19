// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func validReloadTestOutcome() proxy.ReloadOutcome {
	return proxy.ReloadOutcome{InstanceID: "process", Generation: 1, Trigger: "api", CanonicalPolicyHash: strings.Repeat("a", 64), CandidateSourceHash: strings.Repeat("b", 64), AcceptedSourceHash: strings.Repeat("b", 64), Verdict: proxy.ReloadAccepted, RestartRequiredFields: []string{}, ReloadAvailable: true, WatcherState: "watching"}
}

func TestReloadCommandVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name, verdict    string
		pending, wantErr bool
	}{
		{"accepted", proxy.ReloadAccepted, false, false},
		{"dedup", proxy.ReloadUnchanged, false, false},
		{"rejected", proxy.ReloadRejected, false, true},
		{"partial", proxy.ReloadRestartRequired, true, true},
		{"uncertain", proxy.ReloadUncertain, false, true},
		{"unavailable", proxy.ReloadUnavailable, false, true},
		{"compensated", proxy.ReloadCompensated, false, true},
		{"unknown", "new-server-verdict", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := validReloadTestOutcome()
			out.Verdict, out.PendingRestart, out.Reason = tc.verdict, tc.pending, "field requires attention"
			if tc.pending {
				out.RestartRequiredFields = []string{"metrics_listen"}
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/v1/config/reload" || r.Header.Get("Authorization") != "Bearer "+testToken {
					t.Errorf("wrong request: %s %s", r.Method, r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer srv.Close()
			cmd := ReloadCmd()
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetArgs([]string{"--api-url", srv.URL, "--api-token", testToken, "--json"})
			err := cmd.Execute()
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v output=%s", err, buf.String())
			}
			if tc.verdict != "new-server-verdict" && !strings.Contains(buf.String(), tc.verdict) {
				t.Fatalf("missing verdict: %s", buf.String())
			}
		})
	}
}

func TestReloadRecoveryBypassesMalformedLocalConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidate.yaml")
	if err := os.WriteFile(path, []byte("mode: [broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/config/status" {
			t.Errorf("wrong status request")
		}
		_ = json.NewEncoder(w).Encode(validReloadTestOutcome())
	}))
	defer srv.Close()
	t.Setenv("PIPELOCK_API_URL", srv.URL)
	t.Setenv("PIPELOCK_KILLSWITCH_API_TOKEN", testToken)
	cmd := ReloadCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--status", "--config", path})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestReloadMalformedOutcomeFails(t *testing.T) {
	for _, raw := range []string{"", "null", "{}", `{"verdict":"accepted"}`, `{"instance_id":"x","instance_id":"y"}`, `{} {}`, `{"verdict":42}`} {
		t.Run(raw, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(raw)) }))
			defer srv.Close()
			client := newClient(endpoint{URL: srv.URL, Token: testToken})
			if _, err := client.ConfigReload(t.Context(), false); err == nil {
				t.Fatalf("accepted malformed %q", raw)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*proxy.ReloadOutcome)
	}{
		{"generation", func(o *proxy.ReloadOutcome) { o.Generation = 0 }},
		{"hash", func(o *proxy.ReloadOutcome) { o.CanonicalPolicyHash = "bad" }},
		{"source", func(o *proxy.ReloadOutcome) { o.CandidateSourceHash = "bad" }},
		{"pending", func(o *proxy.ReloadOutcome) { o.PendingRestart = true }},
		{"accepted with restart fields", func(o *proxy.ReloadOutcome) {
			o.PendingRestart = true
			o.RestartRequiredFields = []string{"metrics_listen"}
		}},
		{"partial without fields", func(o *proxy.ReloadOutcome) { o.Verdict = proxy.ReloadRestartRequired }},
		{"missing reason", func(o *proxy.ReloadOutcome) { o.Verdict = proxy.ReloadRejected }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := validReloadTestOutcome()
			tc.mutate(&out)
			if err := validateReloadOutcome(out); err == nil {
				t.Fatalf("accepted %+v", out)
			}
		})
	}
}

func TestReloadCommandOutputAndFailure(t *testing.T) {
	out := validReloadTestOutcome()
	out.CandidateSourceHash, out.AcceptedSourceHash = "defaults", ""
	out.Reason = "configuration unchanged"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	cmd := ReloadCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--api-url", srv.URL, "--api-token", testToken})
	if err := cmd.Execute(); err != nil || !strings.Contains(buf.String(), "generation=1") || !strings.Contains(buf.String(), out.Reason) {
		t.Fatalf("text output=%q err=%v", buf.String(), err)
	}
	for _, tc := range []struct {
		name   string
		args   []string
		writer io.Writer
	}{
		{"JSON", []string{"--json"}, errWriter{}},
		{"text status", nil, &reloadOutputErrorWriter{failStatus: true}},
		{"text reason", nil, &reloadOutputErrorWriter{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := ReloadCmd()
			cmd.SetOut(tc.writer)
			cmd.SetArgs(append([]string{"--api-url", srv.URL, "--api-token", testToken}, tc.args...))
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "boom") {
				t.Fatalf("output error not propagated: %v", err)
			}
		})
	}
	srv.Close()
	client := newClient(endpoint{URL: srv.URL, Token: testToken})
	if _, err := client.ConfigReload(t.Context(), true); err == nil {
		t.Fatal("unavailable daemon reported success")
	}
}

type reloadOutputErrorWriter struct {
	wroteStatus bool
	failStatus  bool
}

func (w *reloadOutputErrorWriter) Write(p []byte) (int, error) {
	isStatus := !w.wroteStatus
	w.wroteStatus = true
	if isStatus == w.failStatus {
		return errWriter{}.Write(p)
	}
	return len(p), nil
}

func TestReloadMalformedRequiredWireFields(t *testing.T) {
	raw, err := json.Marshal(validReloadTestOutcome())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, field, value string }{
		{"absent", "pending_restart", ""},
		{"null", "watcher_state", "null"},
		{"wrong type", "activation_generation", `"one"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			if tc.value == "" {
				delete(fields, tc.field)
			} else {
				fields[tc.field] = json.RawMessage(tc.value)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(fields)
			}))
			defer srv.Close()
			client := newClient(endpoint{URL: srv.URL, Token: testToken})
			if _, err := client.ConfigReload(t.Context(), false); err == nil {
				t.Fatalf("accepted malformed field %s", tc.field)
			}
		})
	}
}
