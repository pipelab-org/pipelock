// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func TestDLPKeywordsReloadRestrictions(t *testing.T) {
	for _, tc := range []struct {
		name, mode       string
		receipts, reject bool
	}{{"balanced", config.ModeBalanced, false, false}, {"strict", config.ModeStrict, false, true}, {"required receipts", config.ModeBalanced, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			old := config.Defaults()
			old.Mode = tc.mode
			old.FlightRecorder.RequireReceipts = tc.receipts
			old.DLP.Patterns = []config.DLPPattern{{Name: "account", Regex: `[0-9]{16}`, Severity: config.SeverityHigh}}
			next := old.Clone()
			next.DLP.Patterns[0].Keywords = []string{"account"}
			if got := reloadDowngradeRejectReason(old, next, config.ValidateReload(old, next)); (got != "") != tc.reject {
				t.Fatalf("rejection=%q", got)
			}
			if got := reloadDowngradeRejectReason(next, next.Clone(), config.ValidateReload(next, next.Clone())); got != "" {
				t.Fatalf("unchanged gate rejected: %s", got)
			}
			// Bundle adapters must not mistake non-bundle keyword weakening for a bundle-only edit.
			if dlpPatternCoverageIdentity(old.DLP.Patterns[0]) == dlpPatternCoverageIdentity(next.DLP.Patterns[0]) {
				t.Fatal("keyword policy missing from runtime identity")
			}
		})
	}
}

func TestDLPKeywordsReloadLifecycle(t *testing.T) {
	const base = "mode: balanced\ndlp:\n  include_defaults: false\n  scan_env: false\n  patterns:\n    - name: account\n      regex: '[0-9]{16}'\n      severity: high\n"
	gated := base + "      keywords: [account]\n"
	s, err := NewServer(ServerOpts{ConfigFile: writeServerTestConfig(t, base), Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.cleanup)
	assertScan := func(want bool) {
		t.Helper()
		found := false
		for _, m := range s.proxy.ScannerPtr().Load().ScanTextForDLP(t.Context(), "3333333333333333").Matches {
			found = found || m.PatternName == "account"
		}
		if found != want {
			t.Fatalf("active generation found=%v want=%v", found, want)
		}
	}
	assertScan(true)
	before := s.ReloadStatus()
	writeReloadCandidate(t, s, gated)
	if out := s.ReloadFile(); out.Verdict != proxy.ReloadAccepted || out.CanonicalPolicyHash == before.CanonicalPolicyHash {
		t.Fatalf("enable: %+v", out)
	}
	assertScan(false)
	hash := s.ReloadStatus().CanonicalPolicyHash
	if out := s.ReloadFile(); out.Verdict != proxy.ReloadUnchanged || out.CanonicalPolicyHash != hash {
		t.Fatalf("unchanged: %+v", out)
	}
	writeReloadCandidate(t, s, gated+"      keyword_window: 0\n")
	if out := s.ReloadFile(); out.Verdict != proxy.ReloadRejected || out.CanonicalPolicyHash != hash {
		t.Fatalf("invalid: %+v", out)
	}
	assertScan(false)
	writeReloadCandidate(t, s, base)
	if out := s.ReloadFile(); out.Verdict != proxy.ReloadAccepted {
		t.Fatalf("recover: %+v", out)
	}
	assertScan(true)
	// A valid gate also applies on first load, without a prior ungated generation.
	initial, err := NewServer(ServerOpts{ConfigFile: writeServerTestConfig(t, gated), Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(initial.cleanup)
	for _, m := range initial.proxy.ScannerPtr().Load().ScanTextForDLP(t.Context(), "3333333333333333").Matches {
		if m.PatternName == "account" {
			t.Fatal("startup gate was inert")
		}
	}
}
