// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"slices"
	"testing"

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
	writeReloadCandidate(t, s, base)
	if out := s.ReloadFile(); out.PendingRestart {
		t.Fatalf("reverted config retained drift: %+v", out)
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
