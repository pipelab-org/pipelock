// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func TestReloadOutcomeDetectorDrift(t *testing.T) {
	base := fmt.Sprintf("mode: balanced\nflight_recorder:\n  enabled: true\n  sign_checkpoints: false\n  dir: %q\ndlp:\n  scan_env: false\n", t.TempDir())
	errout := &syncBuffer{}
	s, err := NewServer(ServerOpts{ConfigFile: writeServerTestConfig(t, base), CaptureOutput: t.TempDir(), Stdout: &syncBuffer{}, Stderr: errout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	candidate := base + "  patterns:\n    - name: sample\n      regex: sample-pattern\n      severity: high\n"
	writeReloadCandidate(t, s, candidate)
	for range 2 {
		out := s.ReloadFile()
		if out.Verdict != proxy.ReloadRestartRequired || !slices.Contains(out.RestartRequiredFields, reloadReceiptDetectorField) || !slices.Contains(out.RestartRequiredFields, reloadCaptureDetectorField) {
			t.Fatalf("missing retained detector drift: %+v", out)
		}
	}
	if !errout.contains("capture redaction uses startup values until restart") || !errout.contains("receipt content check uses startup values until restart") {
		t.Fatal("missing warnings")
	}
	errout.reset()
	writeReloadCandidate(t, s, base)
	if out := s.ReloadFile(); out.PendingRestart || out.Verdict == proxy.ReloadRestartRequired {
		t.Fatalf("reverted config retained drift: %+v", out)
	}
	if errout.contains("uses startup values until restart") {
		t.Fatalf("reverted reload still claimed detector drift:\n%s", errout.String())
	}
}

func TestRejectedReloadDoesNotClaimDetectorDrift(t *testing.T) {
	base := fmt.Sprintf("mode: strict\napi_allowlist:\n  - api.vendor.example\nflight_recorder:\n  enabled: true\n  sign_checkpoints: false\n  dir: %q\ndlp:\n  scan_env: false\n", t.TempDir())
	errout := &syncBuffer{}
	s, err := NewServer(ServerOpts{ConfigFile: writeServerTestConfig(t, base), Stdout: &syncBuffer{}, Stderr: errout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Format("2006-01-02")
	dir := s.proxy.CurrentConfig().FlightRecorder.Dir
	rejected := fmt.Sprintf("mode: strict\napi_allowlist:\n  - api.vendor.example\nflight_recorder:\n  enabled: true\n  sign_checkpoints: false\n  dir: %q\nfetch_proxy:\n  monitoring:\n    path_entropy_exclusions:\n      - host: api.vendor.example\n        path_prefix: /v1/health\n        reason: health probe\n        owner: platform-security\n        expires: %q\ndlp:\n  scan_env: false\n  patterns:\n    - name: sample\n      regex: sample-pattern\n      severity: high\n", dir, expires)
	writeReloadCandidate(t, s, rejected)
	out := s.ReloadFile()
	if out.Verdict != proxy.ReloadRejected || out.PendingRestart {
		t.Fatalf("rejected reload outcome: %+v\nstderr:\n%s", out, errout.String())
	}
	if errout.contains("uses startup values until restart") {
		t.Fatalf("rejected reload claimed detector drift:\n%s", errout.String())
	}
	for _, pattern := range s.proxy.CurrentConfig().DLP.Patterns {
		if pattern.Name == "sample" {
			t.Fatal("rejected pattern was published")
		}
	}
	errout.reset()
	writeReloadCandidate(t, s, base)
	again := s.ReloadFile()
	if again.PendingRestart || again.Verdict == proxy.ReloadRestartRequired || again.Verdict == proxy.ReloadRejected {
		t.Fatalf("startup baseline moved after the rejected candidate: %+v\nstderr:\n%s", again, errout.String())
	}
	if errout.contains("uses startup values until restart") {
		t.Fatalf("unchanged reload claimed detector drift:\n%s", errout.String())
	}
}

func TestSeedDetectionReloadReportsStartupDetector(t *testing.T) {
	base := fmt.Sprintf("mode: balanced\nflight_recorder:\n  enabled: true\n  sign_checkpoints: false\n  dir: %q\nseed_phrase_detection:\n  enabled: false\ndlp:\n  scan_env: false\n", t.TempDir())
	errout := &syncBuffer{}
	s, err := NewServer(ServerOpts{ConfigFile: writeServerTestConfig(t, base), Stdout: &syncBuffer{}, Stderr: errout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	writeReloadCandidate(t, s, fmt.Sprintf("mode: balanced\nflight_recorder:\n  enabled: true\n  sign_checkpoints: false\n  dir: %q\nseed_phrase_detection:\n  enabled: true\ndlp:\n  scan_env: false\n", s.proxy.CurrentConfig().FlightRecorder.Dir))
	out := s.ReloadFile()
	if out.Verdict != proxy.ReloadRestartRequired || !slices.Contains(out.RestartRequiredFields, reloadReceiptDetectorField) {
		t.Fatalf("seed enable outcome: %+v\nstderr:\n%s", out, errout.String())
	}
	if s.proxy.CurrentConfig().SeedPhraseDetection.Enabled == nil || !*s.proxy.CurrentConfig().SeedPhraseDetection.Enabled {
		t.Fatalf("seed enable was not applied: %+v", s.proxy.CurrentConfig().SeedPhraseDetection)
	}
	if !errout.contains("seed_phrase_detection changed; receipt content check uses startup values until restart") {
		t.Fatalf("missing seed notice:\n%s", errout.String())
	}
}

// Strict mode refuses any reload that carries a warning. The startup detector
// notice is reported on stderr and as a restart field, not as a reload warning,
// so a strict deployment can still add a canary token without a restart.
func TestStrictReloadAppliesCanaryWithDetectorNotice(t *testing.T) {
	base := fmt.Sprintf("mode: strict\napi_allowlist:\n  - api.vendor.example\nflight_recorder:\n  enabled: true\n  sign_checkpoints: false\n  dir: %q\n", t.TempDir())
	errout := &syncBuffer{}
	s, err := NewServer(ServerOpts{ConfigFile: writeServerTestConfig(t, base), Stdout: &syncBuffer{}, Stderr: errout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	writeReloadCandidate(t, s, base+"canary_tokens:\n  enabled: true\n  tokens:\n    - name: strict-canary\n      value: strict-canary-value-0001\n")
	out := s.ReloadFile()
	if out.Verdict != proxy.ReloadRestartRequired || !slices.Contains(out.RestartRequiredFields, reloadReceiptDetectorField) {
		t.Fatalf("strict canary reload outcome: %+v\nstderr:\n%s", out, errout.String())
	}
	if slices.Contains(out.RestartRequiredFields, reloadCaptureDetectorField) {
		t.Fatalf("capture field reported without a capture writer: %+v", out)
	}
	if got := s.proxy.CurrentConfig().CanaryTokens.Tokens; len(got) != 1 || got[0].Name != "strict-canary" {
		t.Fatalf("canary reload not applied: %+v", got)
	}
	if !errout.contains("receipt content check uses startup values until restart") {
		t.Fatalf("missing receipt notice:\n%s", errout.String())
	}
}
