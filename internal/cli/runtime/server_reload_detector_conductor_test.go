//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"os"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

const detectorBundlePattern = "dlp:\n  patterns:\n    - name: Custom sample\n      regex: CobaltHazelnut[0-9]{5}\n      severity: high\n"

func hasDetectorRestartField(out proxy.ReloadOutcome) bool {
	return slices.Contains(out.RestartRequiredFields, reloadReceiptDetectorField)
}

// The receipt scanner is built from the local config before any cached bundle
// is recovered, and every restart rebuilds it the same way. Restart drift is
// therefore local file against local startup config; bundle values never count.
func TestConductorDetectorInputsAreNotRestartDrift(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	fixture, signer := newConductorApplyTestServer(t)
	localBody, err := os.ReadFile(fixture.opts.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	fixture.cleanup()
	errout := &syncBuffer{}
	s, err := NewServer(ServerOpts{ConfigFile: fixture.opts.ConfigFile, Stdout: &syncBuffer{}, Stderr: errout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	if s.recorder == nil || !s.detectorStartupConfig.FlightRecorder.Redact {
		t.Fatal("fixture has no redacting recorder")
	}
	bundle := signedRuntimePolicyBundle(t, signer, "detector", 1, "", "mode: balanced\n"+detectorBundlePattern)
	if _, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatal(err)
	}
	if out := s.ReloadStatus(); hasDetectorRestartField(out) || out.Verdict == proxy.ReloadRestartRequired {
		t.Fatalf("runtime bundle reported as restart-fixable detector drift: %+v", out)
	}
	if errout.contains("uses startup values until restart") || !errout.contains("conductor policy changed dlp.patterns") {
		t.Fatalf("bundle apply must use the Conductor notice, not a restart promise:\n%s", errout.String())
	}
	// An operator reload of the unchanged local file after a bundle apply has
	// no local drift to report.
	if out := s.ReloadFile(); hasDetectorRestartField(out) {
		t.Fatalf("no-op local reload after bundle apply reported detector drift: %+v", out)
	}

	s.cleanup()
	restartOut := &syncBuffer{}
	restarted, err := NewServer(ServerOpts{ConfigFile: s.opts.ConfigFile, Stdout: &syncBuffer{}, Stderr: restartOut})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.cleanup)
	if out := restarted.ReloadStatus(); hasDetectorRestartField(out) || out.Verdict == proxy.ReloadRestartRequired {
		t.Fatalf("recovered bundle left restart-only detector drift: %+v", out)
	}
	if !restartOut.contains("conductor policy changed dlp.patterns") || restartOut.contains("uses startup values until restart") {
		t.Fatalf("missing recovered-policy detector warning:\n%s", restartOut.String())
	}
	if restarted.liveConfig() == restarted.detectorLocalConfig {
		t.Fatal("recovery moved the local detector baseline")
	}

	// Saving the bundle's value into the local file is local drift: the
	// retained scanner still lacks it and a restart would add it.
	writeReloadCandidate(t, restarted, string(localBody)+detectorBundlePattern)
	if out := restarted.ReloadFile(); !hasDetectorRestartField(out) {
		t.Fatalf("local copy of a recovered value not reported: %+v", out)
	}
	// Restoring the startup local file clears it.
	writeReloadCandidate(t, restarted, string(localBody))
	if out := restarted.ReloadFile(); hasDetectorRestartField(out) {
		t.Fatalf("startup local file reported as detector drift: %+v", out)
	}
}
