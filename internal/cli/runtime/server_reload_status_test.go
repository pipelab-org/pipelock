// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func reloadStatusServer(t *testing.T) *Server {
	t.Helper()
	path := writeServerTestConfig(t, "mode: balanced\n")
	s, err := NewServer(ServerOpts{ConfigFile: path, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	return s
}

func writeReloadCandidate(t *testing.T, s *Server, body string) {
	t.Helper()
	if err := os.WriteFile(s.opts.ConfigFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReloadOutcomeFileLifecycle(t *testing.T) {
	s := reloadStatusServer(t)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", serverTestEphemeralListen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	restartListen := ln.Addr().String()
	initial := s.ReloadStatus()
	if initial.InstanceID == "" || initial.Generation != 1 || !initial.ReloadAvailable {
		t.Fatalf("startup: %+v", initial)
	}
	writeReloadCandidate(t, s, "mode: balanced\n# comment only\n")
	comment := s.ReloadFile()
	if comment.Verdict != proxy.ReloadAccepted || comment.Generation != initial.Generation || comment.CanonicalPolicyHash != initial.CanonicalPolicyHash || comment.AcceptedSourceHash == initial.AcceptedSourceHash {
		t.Fatalf("comment: %+v, initial %+v", comment, initial)
	}
	for _, tc := range []struct {
		name, body, verdict string
		advance, pending    bool
	}{
		{"accepted", "mode: strict\napi_allowlist:\n  - api.vendor.example\n", proxy.ReloadAccepted, true, false},
		{"repeat", "mode: strict\napi_allowlist:\n  - api.vendor.example\n", proxy.ReloadUnchanged, false, false},
		{"restart only", "mode: strict\napi_allowlist:\n  - api.vendor.example\nmetrics_listen: '127.0.0.1:0'\n", proxy.ReloadRestartRequired, false, true},
		{"mixed", "mode: strict\napi_allowlist:\n  - api.vendor.example\nexplain_blocks: true\nmetrics_listen: '127.0.0.1:0'\n", proxy.ReloadRestartRequired, true, true},
		{"invalid", "mode: [\n", proxy.ReloadRejected, false, true},
		{"revert drift", "mode: strict\napi_allowlist:\n  - api.vendor.example\nexplain_blocks: true\n", proxy.ReloadAccepted, false, false},
		{"downgrade", "mode: balanced\n", proxy.ReloadRejected, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := s.ReloadStatus()
			writeReloadCandidate(t, s, strings.ReplaceAll(tc.body, "127.0.0.1:0", restartListen))
			out := s.ReloadFile()
			if out.Verdict != tc.verdict || out.PendingRestart != tc.pending || out.InstanceID != initial.InstanceID || out.CandidateSourceHash == "" {
				t.Fatalf("outcome: %+v", out)
			}
			wantGen := before.Generation
			if tc.advance {
				wantGen++
			}
			if out.Generation != wantGen {
				t.Fatalf("generation=%d want %d; %+v", out.Generation, wantGen, out)
			}
			if out.PendingRestart && strings.Join(out.RestartRequiredFields, ",") != "metrics_listen" {
				t.Fatalf("restart fields: %v", out.RestartRequiredFields)
			}
			if tc.verdict == proxy.ReloadRejected && (out.CanonicalPolicyHash != before.CanonicalPolicyHash || out.AcceptedSourceHash != before.AcceptedSourceHash) {
				t.Fatalf("rejection changed active identity: before=%+v after=%+v", before, out)
			}
			if tc.verdict == proxy.ReloadRestartRequired && out.AcceptedSourceHash != before.AcceptedSourceHash {
				t.Fatalf("partial candidate mislabeled fully accepted: %+v", out)
			}
		})
	}
	if err := os.Remove(s.opts.ConfigFile); err != nil {
		t.Fatal(err)
	}
	before := s.ReloadStatus()
	missing := s.ReloadFile()
	if missing.Verdict != proxy.ReloadRejected || missing.CandidateSourceHash != "" || missing.Generation != before.Generation {
		t.Fatalf("missing: %+v", missing)
	}
	other := reloadStatusServer(t)
	if other.ReloadStatus().InstanceID == initial.InstanceID {
		t.Fatal("restart instance identity reused")
	}
}

func TestReloadOutcomeOwnSerializedResult(t *testing.T) {
	s := reloadStatusServer(t)
	writeReloadCandidate(t, s, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	const callers = 4
	results := make(chan proxy.ReloadOutcome, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() { results <- s.ReloadFile() })
	}
	wg.Wait()
	close(results)
	accepted := 0
	for out := range results {
		if out.Verdict == proxy.ReloadAccepted {
			accepted++
		} else if out.Verdict != proxy.ReloadUnchanged {
			t.Fatalf("unexpected %+v", out)
		}
		if out.Generation != 2 {
			t.Fatalf("invented generation: %+v", out)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted calls=%d want 1", accepted)
	}
}

func TestReloadOutcomeDedupSkipsReconstruction(t *testing.T) {
	// Isolate the fast path from installed bundles, which must be re-resolved
	// before their effective candidate can be compared with the live policy.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	s := reloadStatusServer(t)
	writeReloadCandidate(t, s, "mode: balanced\nexplain_blocks: true\n")
	first := s.ReloadFile()
	if first.Verdict != proxy.ReloadAccepted {
		t.Fatalf("first: %+v", first)
	}
	live := s.proxy.CurrentConfig()
	s.scannerConstructor = func(*config.Config) (*scanner.Scanner, error) {
		t.Error("identical coalesced candidate rebuilt scanner")
		return nil, errors.New("unexpected reconstruction")
	}
	s.recordReloadSuccess(live.Hash())
	if out := s.ReloadFile(); out.Verdict != proxy.ReloadUnchanged || out.Generation != first.Generation || s.proxy.CurrentConfig() != live {
		t.Fatalf("dedup: %+v", out)
	}
}

func TestReloadOutcomeDistinctSerializedResults(t *testing.T) {
	s := reloadStatusServer(t)
	writeReloadCandidate(t, s, "mode: balanced\nexplain_blocks: true\n")
	firstLoaded := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	paused := false
	t.Cleanup(setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server == s && !paused {
			paused = true
			close(firstLoaded)
			<-release
		}
	}))
	first := make(chan proxy.ReloadOutcome, 1)
	second := make(chan proxy.ReloadOutcome, 1)
	var workers sync.WaitGroup
	t.Cleanup(func() { unblock(); workers.Wait() })
	workers.Go(func() { first <- s.ReloadFile() })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	select {
	case <-firstLoaded:
	case <-ctx.Done():
		t.Fatal("first reload did not publish")
	}
	writeReloadCandidate(t, s, "mode: balanced\nexplain_blocks: false\n")
	workers.Go(func() { second <- s.ReloadFile() })
	unblock()
	workers.Wait()
	a, b := <-first, <-second
	if a.Verdict != proxy.ReloadAccepted || b.Verdict != proxy.ReloadAccepted || a.Generation != 2 || b.Generation != 3 || a.CandidateSourceHash == b.CandidateSourceHash || a.CanonicalPolicyHash == b.CanonicalPolicyHash {
		t.Fatalf("callers lost their own transaction: first=%+v second=%+v", a, b)
	}
	if s.ReloadStatus().CandidateSourceHash != b.CandidateSourceHash {
		t.Fatal("latest snapshot differs from final transaction")
	}
}

func TestReloadOutcomeSignalAndFileShareSnapshot(t *testing.T) {
	s := reloadStatusServer(t)
	for _, tc := range []struct {
		trigger config.ReloadTrigger
		want    string
	}{{config.ReloadTriggerSignal, "signal"}, {config.ReloadTriggerFile, "fsnotify"}} {
		s.handleConfigReload(config.ReloadEvent{Config: s.proxy.CurrentConfig().Clone(), Trigger: tc.trigger})
		if got := s.ReloadStatus(); got.Trigger != tc.want || got.Generation != 1 {
			t.Fatalf("snapshot=%+v", got)
		}
	}
	s.setReloadWatcherState("failed")
	if got := s.ReloadStatus(); got.WatcherState != "failed" || !got.ReloadAvailable {
		t.Fatalf("watch failure obscured API availability: %+v", got)
	}
	// Returned slices are detached from the daemon-owned snapshot.
	s.reloadOutcome.RestartRequiredFields = []string{"metrics_listen"}
	snapshotCopy := s.ReloadStatus()
	snapshotCopy.RestartRequiredFields[0] = "corrupt"
	if s.ReloadStatus().RestartRequiredFields[0] != "metrics_listen" {
		t.Fatal("snapshot aliases state")
	}
}

func TestReloadOutcomePostPublicationPanic(t *testing.T) {
	s := reloadStatusServer(t)
	writeReloadCandidate(t, s, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	restore := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server == s {
			panic("synthetic post-publication failure")
		}
	})
	t.Cleanup(restore)
	out := s.ReloadFile()
	if out.Verdict != proxy.ReloadUncertain || out.Generation != 2 || out.AcceptedSourceHash != "" || !s.killswitch.IsActive() {
		t.Fatalf("post-publication outcome: %+v", out)
	}
	if strings.Contains(out.Reason, "unchanged") || strings.Contains(out.Reason, "synthetic") {
		t.Fatalf("unsafe/false reason: %s", out.Reason)
	}
	// A later syntactically valid reload cannot clear uncertain admission.
	writeReloadCandidate(t, s, "mode: strict\napi_allowlist:\n  - api.vendor.example\nexplain_blocks: true\n")
	restore()
	out = s.ReloadFile()
	if out.Verdict != proxy.ReloadUncertain || !s.killswitch.IsActive() || !strings.Contains(out.Reason, "uncertain") {
		t.Fatalf("uncertainty cleared without recovery: %+v", out)
	}
	for _, body := range []string{"mode: [broken\n", "mode: balanced\n"} {
		writeReloadCandidate(t, s, body)
		if rejected := s.ReloadFile(); rejected.Verdict != proxy.ReloadUncertain || !s.killswitch.IsActive() || rejected.Generation != out.Generation {
			t.Fatalf("rejected candidate obscured runtime uncertainty: %+v", rejected)
		}
	}
}

func TestReloadOutcomeSafeReason(t *testing.T) {
	err := errors.New("rejected: security downgrade from strict mode (field\n\x1b)")
	if got := safeReloadReason(err); strings.ContainsAny(got, "\n\x1b") || !strings.Contains(got, "field") {
		t.Fatalf("unsafe reason %q", got)
	}
	if got := safeReloadReason(errors.New("secret-value")); strings.Contains(got, "secret-value") {
		t.Fatalf("raw error exposed: %q", got)
	}
}

func TestReloadOutcomeReconciliationRemainsPending(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", serverTestEphemeralListen)
	if err != nil {
		t.Fatal(err)
	}
	metricsAddr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	body := "mode: balanced\nmetrics_listen: " + metricsAddr + "\n"
	path := writeServerTestConfig(t, body)
	s, err := NewServer(ServerOpts{ConfigFile: path, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	before := s.ReloadStatus()
	body += "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    owner: search-team\n    reason: local index\n    expires_at: " + time.Now().UTC().Add(time.Hour).Format(time.RFC3339) + "\n"
	writeReloadCandidate(t, s, body)
	for range 2 {
		out := s.ReloadFile()
		if out.Verdict != proxy.ReloadRestartRequired || strings.Join(out.RestartRequiredFields, ",") != "containment.loopback_services" || out.AcceptedSourceHash != before.AcceptedSourceHash || out.Generation != before.Generation+1 {
			t.Fatalf("unobserved reconciliation reported complete: %+v", out)
		}
	}
}

func TestReloadOutcomeSharedAdminMount(t *testing.T) {
	path := writeServerTestConfig(t, "mode: balanced\nkill_switch:\n  api_token: reload-test-token\n")
	s, err := NewServer(ServerOpts{ConfigFile: path, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/config/reload", nil)
	req.Header.Set("Authorization", "Bearer reload-test-token")
	w := httptest.NewRecorder()
	s.proxy.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("shared mount=%d %s", w.Code, w.Body.String())
	}
	var out proxy.ReloadOutcome
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Trigger != "api" || out.InstanceID == "" {
		t.Fatalf("not daemon-owned: %+v", out)
	}
}

func TestReloadOutcomeAdminBootstrapNeedsRestart(t *testing.T) {
	s := reloadStatusServer(t)
	writeReloadCandidate(t, s, "mode: balanced\nkill_switch:\n  api_token: bootstrap-test-token\n")
	out := s.ReloadFile()
	if out.Verdict != proxy.ReloadRestartRequired || !out.PendingRestart || strings.Join(out.RestartRequiredFields, ",") != "kill_switch.api_token" {
		t.Fatalf("bootstrap: %+v", out)
	}
	if s.proxy.SessionAPI() != nil {
		t.Fatal("reload created admin handler without startup")
	}
}

func TestReloadOutcomeUnavailableSource(t *testing.T) {
	s, _ := newTestServer(t, nil)
	out := s.ReloadFile()
	if out.Verdict != proxy.ReloadUnavailable || out.ReloadAvailable || out.Generation != 1 {
		t.Fatalf("unavailable: %+v", out)
	}
}
