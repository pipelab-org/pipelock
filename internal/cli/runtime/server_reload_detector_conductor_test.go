//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// A Conductor bundle is applied after the receipt scanner is built, and every
// restart rebuilds that scanner from the local config before recovery. Its
// detector inputs therefore must not be reported as drift a restart applies.
func TestConductorDetectorInputsAreNotRestartDrift(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	s, signer := newConductorApplyTestServer(t)
	if s.recorder == nil || !s.detectorStartupConfig.FlightRecorder.Redact {
		t.Fatal("fixture has no redacting recorder")
	}
	bundle := signedRuntimePolicyBundle(t, signer, "detector", 1, "", "mode: balanced\ndlp:\n  patterns:\n    - name: Custom sample\n      regex: CobaltHazelnut[0-9]{5}\n      severity: high\n")
	if _, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatal(err)
	}
	if out := s.ReloadStatus(); slices.Contains(out.RestartRequiredFields, reloadReceiptDetectorField) || out.Verdict == proxy.ReloadRestartRequired && !out.PendingRestart {
		t.Fatalf("runtime bundle reported as restart-fixable detector drift: %+v", out)
	}

	s.cleanup()
	errout := &syncBuffer{}
	restarted, err := NewServer(ServerOpts{ConfigFile: s.opts.ConfigFile, Stdout: &syncBuffer{}, Stderr: errout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.cleanup)
	out := restarted.ReloadStatus()
	if slices.Contains(out.RestartRequiredFields, reloadReceiptDetectorField) || out.Verdict == proxy.ReloadRestartRequired && !out.PendingRestart {
		t.Fatalf("recovered bundle left restart-only detector drift: %+v", out)
	}
	if !errout.contains("conductor policy changed dlp.patterns") || !errout.contains("restarting does not apply") {
		t.Fatalf("missing recovered-policy detector warning:\n%s", errout.String())
	}
	// Later local drift is still measured, against the recovered policy.
	candidate := restarted.liveConfig().Clone()
	candidate.CanaryTokens.Enabled = true
	candidate.CanaryTokens.Tokens = append(candidate.CanaryTokens.Tokens, canaryTokenForDetectorTest())
	if err := restarted.Reload(candidate); err != nil {
		t.Fatal(err)
	}
	if out := restarted.ReloadStatus(); !slices.Contains(out.RestartRequiredFields, reloadReceiptDetectorField) {
		t.Fatalf("local detector drift after recovery not reported: %+v", out)
	}
}

func canaryTokenForDetectorTest() config.CanaryToken {
	return config.CanaryToken{Name: "local-canary", Value: "local-canary-value-0001"}
}
