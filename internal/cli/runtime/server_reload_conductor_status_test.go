//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/getsentry/sentry-go"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestReloadOutcomeConductorSentryScrubberDrift(t *testing.T) {
	t.Setenv("SENTRY_DSN", "")
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	s, signer := newConductorApplyTestServerWithConfig(t, "sentry:\n  enabled: true\n  dsn: https://k@o.vendor.example/1\n")
	beforeSend := sentry.CurrentHub().Client().Options().BeforeSend
	const sample = "CobaltHazelnut48372"
	if got := beforeSend(&sentry.Event{Message: sample}, nil); got == nil || got.Message != sample {
		t.Fatal("startup scrubber already covers the sample")
	}
	bundle := signedRuntimePolicyBundle(t, signer, "scrubber", 1, "", "mode: balanced\ndlp:\n  patterns:\n    - name: Custom sample\n      regex: CobaltHazelnut[0-9]{5}\n      severity: high\n")
	if _, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatal(err)
	}
	if s.proxy.ScannerPtr().Load().ScanTextForDLP(t.Context(), sample).Clean {
		t.Fatal("Conductor strengthening did not reach the scanner")
	}
	out := s.ReloadStatus()
	if out.Verdict != proxy.ReloadRestartRequired || !slices.Contains(out.RestartRequiredFields, reloadSentryScrubberField) || out.AcceptedSourceHash != "" {
		t.Fatalf("durable finality hid scrubber drift: %+v", out)
	}

	// Cached-policy recovery must make restart a real scrubber remedy.
	s.cleanup()
	restarted, err := NewServer(ServerOpts{ConfigFile: s.opts.ConfigFile, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.cleanup)
	got := sentry.CurrentHub().Client().Options().BeforeSend(&sentry.Event{Message: sample}, nil)
	if got == nil || strings.Contains(got.Message, sample) || restarted.sentry.ScrubberNeedsRestart(restarted.liveConfig()) {
		t.Fatal("restart did not bind the scrubber to the recovered policy")
	}
	s = restarted
	// Other follower-local pending fields survive; the scrubber observation is
	// recomputed against the actual restored policy at the final boundary.
	s.reloadMu.Lock()
	before := s.reloadSnapshotLocked()
	before.RestartRequiredFields = []string{reloadSentryScrubberField, "metrics_listen"}
	before.PendingRestart = true
	cfg := s.liveConfig().Clone()
	s.reloadDurablePending = true
	err = s.reloadLockedRestoringPriorPolicy(cfg)
	s.reloadDurablePending = false
	s.finishConductorReloadLocked(before, true, err)
	out = s.reloadSnapshotLocked()
	s.reloadMu.Unlock()
	if err != nil || slices.Contains(out.RestartRequiredFields, reloadSentryScrubberField) || !slices.Contains(out.RestartRequiredFields, "metrics_listen") {
		t.Fatalf("restored policy retained stale scrubber drift or lost local drift: err=%v out=%+v", err, out)
	}
}

func TestReloadOutcomeConductorFinality(t *testing.T) {
	for _, failRestore := range []bool{false, true} {
		name := "compensated"
		if failRestore {
			name = "uncertain"
		}
		t.Run(name, func(t *testing.T) {
			s, signer := newConductorApplyTestServer(t)
			first := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: balanced\n")
			applied, err := s.ApplyConductorPolicyBundle(first, ConductorApplyOptions{Resolver: signer.resolver()})
			if err != nil {
				t.Fatal(err)
			}
			before := s.ReloadStatus()
			if before.Trigger != "conductor" || before.Verdict != proxy.ReloadAccepted {
				t.Fatalf("initial apply: %+v", before)
			}
			next := signedRuntimePolicyBundle(t, signer, "next", 2, applied.BundleHash, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
			hash, err := next.CanonicalHash()
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(s.proxy.CurrentConfig().Conductor.BundleCacheDir, "configs", hash+".yaml")
			constructor := s.scannerConstructor
			fired := false
			restore := setReloadAfterProxySwapHookForTest(func(server *Server) {
				if server != s || fired {
					return
				}
				fired = true
				if err := os.Remove(target); err != nil {
					t.Error(err)
				}
				if failRestore {
					s.scannerConstructor = func(*config.Config) (*scanner.Scanner, error) {
						return nil, errors.New("synthetic restoration failure")
					}
				}
			})
			t.Cleanup(restore)
			_, err = s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()})
			restore()
			s.scannerConstructor = constructor
			if err == nil || !fired {
				t.Fatalf("durable activation failure not injected: %v", err)
			}
			out := s.ReloadStatus()
			want := proxy.ReloadCompensated
			if failRestore {
				want = proxy.ReloadUncertain
			}
			if out.Verdict != want || out.Trigger != "conductor" || out.Generation <= before.Generation {
				t.Fatalf("final: %+v", out)
			}
			if out.CanonicalPolicyHash != s.proxy.CurrentConfig().CanonicalPolicyHash() {
				t.Fatal("live policy identity is stale")
			}
			if failRestore && !s.killswitch.IsActive() {
				t.Fatal("uncertain application admitted traffic")
			}
			if !failRestore && out.CanonicalPolicyHash != before.CanonicalPolicyHash {
				t.Fatal("compensation did not restore policy identity")
			}
		})
	}
}

func TestReloadOutcomeConductorPreservesPendingRestart(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	candidate := s.proxy.CurrentConfig().Clone()
	candidate.MetricsListen = "127.0.0.1:0"
	if err := s.Reload(candidate); err != nil {
		t.Fatal(err)
	}
	before := s.ReloadStatus()
	if !before.PendingRestart {
		t.Fatal("fixture did not establish restart drift")
	}
	bundle := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: balanced\n")
	if _, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatal(err)
	}
	out := s.ReloadStatus()
	if !out.PendingRestart || out.Verdict != proxy.ReloadRestartRequired || out.Reason == "" || out.AcceptedSourceHash != "" {
		t.Fatalf("Conductor misreported outstanding restart drift: %+v", out)
	}
}

func TestReloadOutcomeConductorRejectedIdentity(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	first := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	applied, err := s.ApplyConductorPolicyBundle(first, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatal(err)
	}
	before := s.ReloadStatus()
	next := signedRuntimePolicyBundle(t, signer, "next", 2, applied.BundleHash, "mode: balanced\n")
	if _, err := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()}); err == nil {
		t.Fatal("downgrade accepted")
	}
	out := s.ReloadStatus()
	if out.Verdict != proxy.ReloadRejected || out.Generation != before.Generation || out.CanonicalPolicyHash != before.CanonicalPolicyHash || out.AcceptedSourceHash != before.AcceptedSourceHash || out.CandidateSourceHash == before.CandidateSourceHash {
		t.Fatalf("rejection changed active identity: before=%+v after=%+v", before, out)
	}
}

func TestReloadOutcomeConductorRestartIdentity(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	bundle := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	if _, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatal(err)
	}
	before := s.ReloadStatus()
	s.cleanup()
	restarted, err := NewServer(ServerOpts{ConfigFile: s.opts.ConfigFile, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.cleanup)
	out := restarted.ReloadStatus()
	if out.InstanceID == before.InstanceID || out.Trigger != "conductor" || out.AcceptedSourceHash != "" || out.Verdict != proxy.ReloadAccepted || out.CanonicalPolicyHash != before.CanonicalPolicyHash {
		t.Fatalf("cached recovery identity: before=%+v after=%+v", before, out)
	}
}

func TestReloadOutcomeConductorRetainsPriorUncertainty(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	s.killswitch.SetConductorApplyFailure(true, "prior runtime uncertainty")
	before := s.ReloadStatus()
	bundle := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: balanced\n")
	// A modified signed payload is rejected by staging before any reload.
	bundle.Payload.ConfigYAML = "mode: [broken\n"
	if _, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()}); err == nil {
		t.Fatal("modified signed bundle accepted")
	}
	out := s.ReloadStatus()
	if out.Verdict != proxy.ReloadUncertain || out.AcceptedSourceHash != "" || out.Generation != before.Generation || !s.killswitch.IsActive() {
		t.Fatalf("staging rejection obscured prior uncertainty: %+v", out)
	}
}

// A durably committed apply must not report success while the independent
// uncertainty gate (for example a teardown strict denial) still denies traffic.
func TestReloadOutcomeConductorSuccessCannotMaskDenyingGate(t *testing.T) {
	s, _ := newConductorApplyTestServer(t)
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	before := s.reloadSnapshotLocked()
	s.killswitch.SetConductorApplyFailure(true, conductorApplyUncertainMessage)
	s.finishConductorReloadLocked(before, true, nil)
	out := s.reloadSnapshotLocked()
	if out.Verdict != proxy.ReloadUncertain || out.Reason == "" {
		t.Fatalf("success masked a denying gate: %+v", out)
	}
}
