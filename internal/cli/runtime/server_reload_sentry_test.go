// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/getsentry/sentry-go"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

const reloadSentryConfig = "mode: balanced\nsentry:\n  enabled: true\n  dsn: https://k@o.vendor.example/1\n"

func reloadSentryServer(t *testing.T, body string) *Server {
	t.Helper()
	t.Setenv("SENTRY_DSN", "")
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	s, err := NewServer(ServerOpts{ConfigFile: writeServerTestConfig(t, body), Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	return s
}

func TestReloadOutcomeSentryOptionsRemainPending(t *testing.T) {
	for _, edit := range []string{"enabled: false", "environment: changed", "sample_rate: 0.5", "debug: true"} {
		t.Run(edit, func(t *testing.T) {
			s := reloadSentryServer(t, reloadSentryConfig)
			before := s.proxy.CurrentConfig().Sentry
			body := reloadSentryConfig + "  " + edit + "\n"
			if strings.HasPrefix(edit, "enabled:") {
				body = strings.Replace(reloadSentryConfig, "enabled: true", edit, 1)
			}
			writeReloadCandidate(t, s, body)
			out := s.ReloadFile()
			if out.Verdict != proxy.ReloadRestartRequired || !out.PendingRestart || !slices.Contains(out.RestartRequiredFields, "sentry") {
				t.Fatalf("startup Sentry client still bound=%t, outcome=%+v", sentry.CurrentHub().Client() != nil, out)
			}
			if !reflect.DeepEqual(s.proxy.CurrentConfig().Sentry, before) || out.Generation != 1 {
				t.Fatal("reported Sentry config diverged from startup client")
			}
			if again := s.ReloadFile(); again.Verdict != proxy.ReloadRestartRequired {
				t.Fatalf("repeat lost drift: %+v", again)
			}
			writeReloadCandidate(t, s, reloadSentryConfig)
			if reverted := s.ReloadFile(); reverted.PendingRestart {
				t.Fatalf("reverted options kept drift: %+v", reverted)
			}
		})
	}
}

func TestReloadOutcomeSentryScrubberDrift(t *testing.T) {
	const sample = "CobaltHazelnut48372"
	for _, kind := range []string{"patterns", "environment", "secrets file", "same file contents"} {
		t.Run(kind, func(t *testing.T) {
			secretPath := filepath.Join(t.TempDir(), "values.txt")
			base := reloadSentryConfig + "dlp:\n  scan_env: false\n"
			candidate := base
			switch kind {
			case "patterns":
				candidate += "  patterns:\n    - name: Custom sample\n      regex: CobaltHazelnut[0-9]{5}\n      severity: high\n"
			case "environment":
				t.Setenv("RELOAD_SCRUB_SAMPLE", sample)
				candidate = strings.Replace(base, "scan_env: false", "scan_env: true", 1)
			case "secrets file", "same file contents":
				if err := os.WriteFile(secretPath, []byte("OldHazelnut74629\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				candidate += fmt.Sprintf("  secrets_file: %q\n", secretPath)
				if kind == "same file contents" {
					base = candidate
				}
			}
			s := reloadSentryServer(t, base)
			beforeSend := sentry.CurrentHub().Client().Options().BeforeSend
			if got := beforeSend(&sentry.Event{Message: sample}, nil); got == nil || got.Message != sample {
				t.Fatal("sample does not distinguish startup scrubber")
			}
			if strings.Contains(kind, "file") {
				if err := os.WriteFile(secretPath, []byte(sample+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			candidate += "# candidate\n"
			writeReloadCandidate(t, s, candidate)
			out := s.ReloadFile()
			if got := beforeSend(&sentry.Event{Message: sample}, nil); got == nil || got.Message != sample {
				t.Fatal("test did not retain the actual startup scrubber")
			}
			if result := s.proxy.ScannerPtr().Load().ScanTextForDLP(t.Context(), sample); result.Clean {
				t.Fatal("live DLP strengthening was lost")
			}
			if out.Verdict != proxy.ReloadRestartRequired || !out.PendingRestart || !slices.Contains(out.RestartRequiredFields, reloadSentryScrubberField) {
				t.Fatalf("live DLP blocks but startup scrubber passes sample; outcome=%+v", out)
			}
			if again := s.ReloadFile(); again.Verdict != proxy.ReloadRestartRequired {
				t.Fatalf("repeat lost scrubber drift: %+v", again)
			}
			if kind == "same file contents" {
				if err := os.WriteFile(secretPath, []byte("OldHazelnut74629\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeReloadCandidate(t, s, base+"# revert\n")
			if reverted := s.ReloadFile(); kind == "environment" {
				// The existing environment-scan downgrade guard still rejects it.
				if reverted.Verdict != proxy.ReloadRejected || !reverted.PendingRestart {
					t.Fatalf("environment downgrade lost denial or drift: %+v", reverted)
				}
			} else if reverted.PendingRestart {
				t.Fatalf("restored scrubber inputs kept drift: %+v", reverted)
			}
		})
	}
}
